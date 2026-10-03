import subprocess
import sys
import threading
import time
import os
import argparse
import socket
import json
import logging
from dotenv import load_dotenv

# Load variables from .env if present
load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format='%(message)s'
)
logger = logging.getLogger("Pipeline")

def print_log(msg):
    logger.info(msg)

def prefix_output(process, prefix):
    for line in iter(process.stdout.readline, b''):
        decoded = line.decode('utf-8', errors='replace').rstrip()
        if decoded.startswith("__TELEMETRY__|"):
            try:
                data = json.loads(decoded[14:])
                t = data.get("type")
                if t == "api_request":
                    print_log(f"[{prefix}] Investigation requested for case {data.get('case_id', 'unknown')}")
                elif t == "ingestion_start":
                    print_log(f"[{prefix}] Processing evidence...")
                elif t == "ingestion_complete":
                    print_log(f"[{prefix}] Ingestion completed (code {data.get('returncode')})")
                elif t == "investigation_start":
                    print_log(f"[{prefix}] Starting case {data.get('case_id', 'unknown')}")
                elif t == "node_active":
                    print_log(f"[{data.get('node', 'Node')}] Running")
                elif t == "llm_error":
                    print_log(f"[ERROR] LLM inference failed on {data.get('node')}: {data.get('error')}")
                elif t == "investigation_error":
                    print_log(f"[ERROR] Investigation failed: {data.get('error')}")
                elif t == "investigation_complete":
                    print_log(f"[{prefix}] Investigation complete ({data.get('status')}, {data.get('findings_count')} findings)")
                elif t == "dfkg_write":
                    print_log(f"[{prefix}] Stored finding from {data.get('role')}")
                # Skip other low-level telemetry noise
            except Exception as e:
                pass
        else:
            # Print standard output lines, highlighting errors
            lower_decoded = decoded.lower()
            if "error" in lower_decoded or "exception" in lower_decoded or "traceback" in lower_decoded or "failed" in lower_decoded:
                print_log(f"[ERROR] [{prefix}] {decoded}")
            else:
                print_log(f"[{prefix}] {decoded}")

def run_background_service(command, prefix, cwd=None):
    p = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        cwd=cwd
    )
    t = threading.Thread(target=prefix_output, args=(p, prefix), daemon=True)
    t.start()
    return p

def is_port_listening(host, port):
    """Return True if something is already bound to host:port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1)
        try:
            s.connect((host, port))
            return True
        except (ConnectionRefusedError, OSError):
            return False

def wait_for_kafka(broker="localhost:9092", timeout=60):
    """Poll until Kafka is actually responsive to metadata requests (bypassing docker-proxy)."""
    try:
        from confluent_kafka.admin import AdminClient
    except ImportError:
        # Fallback to simple port check if confluent_kafka is missing
        host, port = broker.split(":")
        port = int(port)
        deadline = time.time() + timeout
        while time.time() < deadline:
            if is_port_listening(host, port):
                time.sleep(10) # Wait an extra 10s for broker to actually boot
                return True
            time.sleep(2)
        return False

    admin = AdminClient({'bootstrap.servers': broker, 'socket.timeout.ms': 2000})
    deadline = time.time() + timeout
    print_log(f"[*] Waiting for Kafka broker at {broker} to become responsive...")
    
    while time.time() < deadline:
        try:
            # list_topics is a reliable way to check if the broker is actually up
            metadata = admin.list_topics(timeout=2)
            if metadata:
                print_log("[*] Kafka broker is up and responsive.")
                return True
        except Exception:
            pass
        time.sleep(3)
        
    print_log(f"[!] Kafka not responsive after {timeout}s - topics may not be created.")
    return False

def main():
    parser = argparse.ArgumentParser(description="Start Full Pipeline")
    parser.add_argument("--start-time", type=str, help="Start time for ingestion (e.g., '2026-08-31 00:00:00')", default=None)
    parser.add_argument("--end-time", type=str, help="End time for ingestion (e.g., '2026-08-31 23:59:59')", default=None)
    args = parser.parse_args()

    cwd = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
    
    print_log("\n[STARTUP] Starting Specula full pipeline...\n")
    print_log("[Docker] Starting infrastructure with docker compose...")
    try:
        subprocess.run(["docker", "compose", "up", "-d"], cwd=cwd, check=True, capture_output=True)
        print_log("[Docker] Waiting for infrastructure to initialize (15s)...")
        time.sleep(15)
    except subprocess.CalledProcessError as e:
        print_log(f"[ERROR] Docker compose failed to start containers. Output: {e.stderr.decode('utf-8', errors='replace')}")
        print_log("[ERROR] Is Docker Desktop running? Please start it and try again.")
        print_log("[ERROR] CRITICAL: Docker compose failed to start. Pipeline will likely fail to connect to Kafka/Neo4j.")
        time.sleep(5)
    except FileNotFoundError:
        print_log("[ERROR] Docker CLI not found. Please install Docker Desktop.")
        time.sleep(5)

    # --- Kafka topic creation (must happen before consumers start) ---
    kafka_broker = os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
    if wait_for_kafka(kafka_broker, timeout=60):
        print_log("[Kafka] Creating/verifying required Kafka topics...")
        try:
            sys.path.insert(0, cwd)
            from src.agents.kafka_utils import create_topics
            create_topics()
            print_log("[Kafka] Ready")
        except Exception as e:
            print_log(f"[ERROR] Topic creation warning: {e}")
    # -----------------------------------------------------------------

    services = []
    try:
        # 0. Start Visualizer API on port 8300 - skip if already listening
        if is_port_listening("localhost", 8300):
            print_log("[VisualizerAPI] Already listening on port 8300 - skipping start.")
        else:
            print_log("[VisualizerAPI] Starting...")
            visualizer = run_background_service(
                [sys.executable, "-m", "uvicorn", "src.agents.visualizer_api:app",
                 "--host", "0.0.0.0", "--port", "8300"],
                "VisualizerAPI",
                cwd
            )
            services.append(visualizer)
            time.sleep(3)  # Give FastAPI time to bind before starting heavy consumers

        # 0b. HITL API on port 8200
        if is_port_listening("localhost", 8200):
            print_log("[HITL] Already listening on port 8200 (Docker container) - skipping local start.")
        else:
            print_log("[HITL] Starting...")
            hitl_svc = run_background_service(
                [sys.executable, "-m", "uvicorn", "src.agents.hitl_api:app",
                 "--host", "0.0.0.0", "--port", "8200"],
                "HITL",
                cwd
            )
            services.append(hitl_svc)
            time.sleep(2)

        # 1. Run LangGraph Orchestrator (Consumer)
        print_log("[Supervisor] Starting...")
        orchestrator = run_background_service([sys.executable, "-m", "src.orchestration.kafka_consumer"], "Supervisor", cwd)
        services.append(orchestrator)

        # 2. Start DFKG Kafka Consumer
        print_log("[DFKG Consumer] Starting...")
        def _run_dfkg_consumer_thread():
            try:
                sys.path.insert(0, cwd)
                from src.agents.kafka_utils import run_dfkg_consumer
                run_dfkg_consumer()
            except Exception as e:
                print_log(f"[ERROR] DFKG consumer error: {e}")
        dfkg_thread = threading.Thread(target=_run_dfkg_consumer_thread, daemon=True, name="DFKGConsumer")
        dfkg_thread.start()

        if args.start_time or args.end_time:
            # Historical Demo Mode
            print_log("[Producer] Starting Log Ingestion (Historical/Demo Mode)...")
            cmd = [sys.executable, "-m", "src.ingestion.run_pipeline"]
            if args.start_time:
                cmd.extend(["--start-time", args.start_time])
            if args.end_time:
                cmd.extend(["--end-time", args.end_time])
            producer = run_background_service(cmd, "Producer", cwd)
            services.append(producer)
        else:
            # Real-time Streaming Mode
            print_log("[Ingestion] Starting Winlogbeat Ingestion Consumer (Real-Time)...")
            winlogbeat_consumer = run_background_service([sys.executable, "-m", "src.ingestion.broker.winlogbeat_consumer"], "Winlogbeat", cwd)
            services.append(winlogbeat_consumer)

            print_log("[Ingestion] Starting Graph/Vector Ingestion Consumer (Real-Time)...")
            ingestion_consumer = run_background_service([sys.executable, "-m", "src.ingestion.broker.ingestion_consumer"], "Ingestion", cwd)
            services.append(ingestion_consumer)
        
        print_log("\n=======================================================")
        print_log("Pipeline is actively running.")
        print_log("Press Ctrl+C to stop all services.")
        print_log("=======================================================\n")
        
        # Keep main thread alive
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        print_log("\n[SYSTEM] Stopping pipeline services...")
    finally:
        for p in services:
            p.terminate()
            p.wait()
        print_log("[SYSTEM] Services stopped.")

if __name__ == "__main__":
    main()

