import subprocess
import sys
import threading
import time
import os
import argparse
from dotenv import load_dotenv

# Load variables from .env if present
load_dotenv()

def prefix_output(process, prefix):
    for line in iter(process.stdout.readline, b''):
        print(f"[{prefix}] {line.decode('utf-8', errors='replace').rstrip()}")

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

def main():
    parser = argparse.ArgumentParser(description="Start Full Pipeline")
    parser.add_argument("--start-time", type=str, help="Start time for ingestion (e.g., '2026-08-31 00:00:00')", default=None)
    parser.add_argument("--end-time", type=str, help="End time for ingestion (e.g., '2026-08-31 23:59:59')", default=None)
    args = parser.parse_args()

    cwd = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
    
    print("[*] Starting infrastructure with docker compose...")
    subprocess.run(["docker", "compose", "up", "-d"], cwd=cwd, check=True)
    
    print("[*] Waiting for infrastructure to initialize (15s)...")
    time.sleep(15)

    services = []
    try:
        # 1. Run LangGraph Orchestrator (Consumer)
        print("[*] Starting Supervisor Orchestrator...")
        orchestrator = run_background_service([sys.executable, "-m", "src.orchestration.kafka_consumer"], "Supervisor", cwd)
        services.append(orchestrator)
        
        if args.start_time or args.end_time:
            # Historical Demo Mode
            print("[*] Starting Log Ingestion Producer (Historical/Demo Mode)...")
            cmd = [sys.executable, "-m", "src.ingestion.run_pipeline"]
            if args.start_time:
                cmd.extend(["--start-time", args.start_time])
            if args.end_time:
                cmd.extend(["--end-time", args.end_time])
            producer = run_background_service(cmd, "Producer", cwd)
            services.append(producer)
        else:
            # Real-time Streaming Mode
            print("[*] Starting Winlogbeat Ingestion Consumer (Real-Time)...")
            winlogbeat_consumer = run_background_service([sys.executable, "-m", "src.ingestion.broker.winlogbeat_consumer"], "Winlogbeat", cwd)
            services.append(winlogbeat_consumer)

            print("[*] Starting Graph/Vector Ingestion Consumer (Real-Time)...")
            ingestion_consumer = run_background_service([sys.executable, "-m", "src.ingestion.broker.ingestion_consumer"], "Ingestion", cwd)
            services.append(ingestion_consumer)
        
        print("\n=======================================================")
        print("Pipeline is actively running.")
        print("Press Ctrl+C to stop all services.")
        print("=======================================================\n")
        
        # Keep main thread alive
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\n[*] Stopping pipeline services...")
    finally:
        for p in services:
            p.terminate()
            p.wait()
        print("[*] Services stopped.")

if __name__ == "__main__":
    main()
