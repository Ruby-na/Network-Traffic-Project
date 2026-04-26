import subprocess
import threading

print("Starting full pipeline...\n")

def run_alerts():
    subprocess.run(["python", "alerts_graph.py"])

def run_severity():
    subprocess.run(["python", "severity_graph.py"])

# run both at the same time
t1 = threading.Thread(target=run_alerts)
t2 = threading.Thread(target=run_severity)

t1.start()
t2.start()

t1.join()
t2.join()

print("\nAll analysis complete.")