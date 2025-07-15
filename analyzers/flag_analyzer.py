from collections import defaultdict
from scapy.all import IP, TCP
from typing import Iterator, Dict, Any

class FlagAnalyzer:
    def analyze(self, packets: Iterator) -> Dict[str, Any]:
        """Analyze packets for suspicious flags"""
        results = {
            'syn_scans': defaultdict(int),
            'malformed_packets': 0,
            'packet_count': 0
        }

        for packet in packets:
            results['packet_count'] += 1
            
            try:
                # Handle both Scapy and PyShark packets
                if hasattr(packet, 'haslayer'):  # Scapy packet
                    self._analyze_scapy(packet, results)
                elif hasattr(packet, 'layers'):  # PyShark packet
                    self._analyze_pyshark(packet, results)
            except Exception:
                continue  # Skip malformed packets
        
        return results

    def _analyze_scapy(self, packet, results):
        if packet.haslayer(IP) and packet.haslayer(TCP):
            flags = packet[TCP].flags
            if 'S' in flags and 'A' not in flags:  # SYN scan
                results['syn_scans'][packet[IP].src] += 1
            if self._is_malformed(packet):
                results['malformed_packets'] += 1

    def _analyze_pyshark(self, packet, results):
        if 'IP' in packet and 'TCP' in packet:
            flags = packet.tcp.flags
            if 'S' in str(flags) and 'A' not in str(flags):
                results['syn_scans'][packet.ip.src] += 1
            if self._is_malformed(packet):
                results['malformed_packets'] += 1

    def _is_malformed(self, packet) -> bool:
        """Check for malformed packets"""
        try:
            if hasattr(packet, 'haslayer'):  # Scapy
                layers = [p for p in packet.layers() if hasattr(p, 'checksum')]
                return any(p.checksum is not None and not p.checksum_valid() for p in layers)
            else:  # PyShark
                layers = [layer for layer in packet.layers if hasattr(layer, 'checksum')]
                return any(getattr(layer, 'checksum_status', '') != 'Correct' for layer in layers)
        except Exception:
            return False
