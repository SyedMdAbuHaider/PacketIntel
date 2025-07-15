from collections import defaultdict
from typing import Iterator, Dict

class ProtocolStats:
    def analyze(self, packets: Iterator) -> Dict[str, int]:
        """Calculate protocol distribution"""
        protocols = defaultdict(int)
        
        for packet in packets:
            protocol = self._get_protocol(packet)
            protocols[protocol] += 1
            
        return dict(protocols)

    def _get_protocol(self, packet) -> str:
        """Get the highest layer protocol name"""
        if hasattr(packet, 'name'):  # Scapy
            return packet.name
        elif hasattr(packet, 'layers'):  # PyShark
            return packet.layers[-1].layer_name
        return 'unknown'
