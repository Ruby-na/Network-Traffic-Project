import os

print("Running full network analyzer...\n")

os.system("python alerts_graph.py")
os.system("python severity_graph.py")