import subprocess
import sys
import threading
import time
import os
import argparse

def prefix_output(process, prefix):
    for line in iter(process.stdout.readline, b''):
        sys.stdout.write(f"[{prefix}] {line.decode('utf-8', errors='replace')}")
        sys.stdout.flush()

def run_background_service(command, prefix, cwd):
    print(f"[*] Starting {prefix}...")
    env = os.environ.copy()
    env["PYTHONPATH"] = cwd
    p = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        cwd=cwd,
        env=env
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
    try:
        subprocess.run(["docker", "compose", "up", "-d"], cwd=cwd, check=True)
    except Exception as e:
        print(f"[!] Failed to start docker compose: {e}")
        print("Please ensure Docker Desktop is running.")
        sys.exit(1)
    
    print("[*] Waiting 10 seconds for Kafka & Neo4j to be ready...")
    time.sleep(10)
    
    services = []
    producer = None
    
    try:
        # 1. Start Visualizer API (if it exists)
        if os.path.exists(os.path.join(cwd, "src", "agents", "visualizer_api.py")):
            services.append(run_background_service([sys.executable, "-m", "src.agents.visualizer_api"], "Visualizer", cwd))
        
        # 2. Start Ingestion Consumer (Vector/DFKG distillation)
        services.append(run_background_service([sys.executable, "-m", "src.ingestion.ingestion_consumer"], "IngestionConsumer", cwd))
        
        # 3. Start Supervisor Orchestrator (Multi-Agent Graph)
        services.append(run_background_service([sys.executable, "-m", "src.orchestration.kafka_consumer"], "Supervisor", cwd))
        
        print("[*] Waiting 5 seconds for consumers to initialize and subscribe to Kafka...")
        time.sleep(5)
        
        # 4. Run Producer (Event Extraction)
        print("[*] Starting Log Ingestion Producer...")
        cmd = [sys.executable, "-m", "src.ingestion.run_pipeline"]
        if args.start_time:
            cmd.extend(["--start-time", args.start_time])
        if args.end_time:
            cmd.extend(["--end-time", args.end_time])
        producer = run_background_service(cmd, "Producer", cwd)
        services.append(producer)
        
        print("\n=======================================================")
        print("[*] Full pipeline is running multiplexed in this console.")
        print("[*] Press Ctrl+C at any time to stop all services.")
        print("=======================================================\n")
        
        # Keep main thread alive
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\n[*] Keyboard interrupt received. Shutting down services...")
    finally:
        for p in services:
            try:
                p.terminate()
            except:
                pass
        print("[*] All python services terminated.")

if __name__ == "__main__":
    main()
