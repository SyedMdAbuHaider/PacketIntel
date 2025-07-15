import json
from pathlib import Path
from typing import Iterator, List

class IOCFilter:
    def __init__(self):
        self.ioc_rules = self._load_ioc_rules()

    def analyze(self, packets: Iterator) -> List[str]:
        """Check packets against IOCs"""
        matches = []
        
        for packet in packets:
            match = self._check_packet(packet)
            if match:
                matches.append(match)
        
        return matches

    def _load_ioc_rules(self) -> dict:
        """Load IOC rules from JSON"""
        try:
            rules_path = Path(__file__).parent.parent / 'rules' / 'malicious_iocs.json'
            with open(rules_path) as f:
                return json.load(f)
        except:
            return {'malicious_ips': [], 'malicious_domains': []}

    def _check_packet(self, packet) -> str:
        """Check packet against IOC rules"""
        try:
            if hasattr(packet, 'haslayer'):  # Scapy
                return self._check_scapy(packet)
            else:  # PyShark
                return self._check_pyshark(packet)
        except:
            return None

    def _check_scapy(self, packet) -> str:
        if packet.haslayer(IP):
            src = packet[IP].src
            dst = packet[IP].dst
            if src in self.ioc_rules['malicious_ips']:
                return f"Malicious source IP: {src}"
            if dst in self.ioc_rules['malicious_ips']:
                return f"Malicious destination IP: {dst}"
        return None

    def _check_pyshark(self, packet) -> str:
        if 'IP' in packet:
            src = packet.ip.src
            dst = packet.ip.dst
            if src in self.ioc_rules['malicious_ips']:
                return f"Malicious source IP: {src}"
            if dst in self.ioc_rules['malicious_ips']:
                return f"Malicious destination IP: {dst}"
        return None
