# 📡 PacketIntel - PCAP Analysis Tool  
**Author**: [Syed Md Abu Haider](https://github.com/SyedMdAbuHaider)  

---

### 🔍 **About**  
PacketIntel is a Python-based tool for analyzing network traffic (PCAP files/live capture) to detect suspicious activities, protocol distributions, and known threats.

---

### 🚀 **Features**  
- **Live Capture**: Monitor network interfaces in real-time  
- **Threat Detection**: SYN scans, malformed packets, IOCs  
- **Protocol Analysis**: Breakdown of TCP/UDP/ICMP traffic  
- **Rich Output**: Colorful console or JSON formatted results  

---

### ⚡ **Quick Start**  

#### **1. Installation**  
```bash
git clone https://github.com/SyedMdAbuHaider/PacketIntel.git  
cd PacketIntel  
python3 -m venv venv  
source venv/bin/activate  
pip install -r requirements.txt  
```

#### **2. Usage**  
```bash
# Analyze PCAP file  
python packetintel.py --pcap capture.pcap  

# Live capture (requires sudo)  
sudo venv/bin/python packetintel.py --live --interface wlo1 --count 100  

# Output formats: text (default), json, rich  
python packetintel.py --pcap traffic.pcap --output json  
```

#### **3. Example Output**  
```
╭────────────── Analysis Results ──────────────╮
│ Suspicious: SYN scans from 192.168.1.5 (3x)  │  
│ Protocols: TCP (68%), UDP (30%), ICMP (2%)   │  
╰──────────────────────────────────────────────╯
```

---

### 🛠 **Requirements**  
- Python 3.8+  
- `scapy`, `pyshark`, `rich`  
- Linux (for live capture)  

---

### 📜 **License**  
MIT License - See [LICENSE](LICENSE)  

---

### 🌐 **Contact**  
For issues/contributions:  
📧 Email: [YourEmail@example.com]  
🐦 Twitter: [@YourHandle]  
