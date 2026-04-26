#️ Network Traffic Intrusion Detection System (Suricata + Python)

## Project Overview
This project is a network security analysis system that uses **Suricata IDS (Intrusion Detection System)** and **Python** to analyze network traffic captured in `.pcap` files. It detects suspicious activity, extracts alerts, and generates structured security reports.

The goal is to simulate how real-world Security Operations Centers (SOC) monitor and analyze network threats.


## Objectives
- Analyze raw network traffic using Suricata IDS
- Detect suspicious or malicious network behavior
- Extract alerts from Suricata logs (`eve.json`)
- Build a Python-based analyzer to process security events
- Generate a readable security report for investigation

## Tools & Technologies
- Suricata IDS (Network Intrusion Detection System)
- Python 3
- JSON (log processing format)
- PCAP files (network traffic capture)
- Git & GitHub (version control)


## Project Structure
Analysis
	suricata_analyzer.py #Python script for log analysis
Data
	sample.pcap #Captured network traffic

Logs
	eve.json
	fast.log
	security_report.txt

README.md


## How It Works

### Network Traffic Capture 
	.pcap file containing network traffic is provided as input.

## Suricata Analysis 
	Sucricata processes the traffic and generates logs:
		- eve.json - structured event data
		- fast.log - alerts and detections

## Python Log Processing
The script suricata_analyzer.py reads eve.json and:
	Filters only security alerts
	Extracts source and destination IPs
	Displays attack signatures and categories

## Report Generation
A final security report is generated containing:
	Detected suspicious IP communication
	Alert signatures
	Attack categories 

## 👤 My Personal Contributions

- Modified and improved the Suricata log analyzer workflow
- Enhanced alert parsing and structured output formatting
- Implemented IP-based aggregation and top attacker detection
- Added severity classification feature (LOW / MEDIUM / HIGH)
- Built optional threat heatmap visualization module
- Improved graph output for presentation-ready display
- Integrated project execution flow using main.py




