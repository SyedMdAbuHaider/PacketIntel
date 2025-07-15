from scapy.all import sniff, PcapReader as ScapyPcapReader, conf, Scapy_Exception
import pyshark
from pathlib import Path
from typing import Union, Iterator, List
from rich.console import Console

console = Console()

class pcap_reader:  # Note: intentionally lowercase for backward compatibility
    """PCAP reading utility class"""
    
    @staticmethod
    def read_pcap(file_path: str, use_scapy: bool = True) -> Union[Iterator, List]:
        """Read packets from a PCAP file"""
        try:
            pcap_path = Path(file_path)
            if not pcap_path.exists():
                raise FileNotFoundError(f"PCAP file not found: {file_path}")
            if pcap_path.stat().st_size == 0:
                raise ValueError("PCAP file is empty")
            
            if use_scapy:
                try:
                    return ScapyPcapReader(str(pcap_path))
                except Scapy_Exception as e:
                    console.print(f"[yellow]Falling back to PyShark: {e}[/yellow]")
                    return pyshark.FileCapture(str(pcap_path))
            return pyshark.FileCapture(str(pcap_path))
        except Exception as e:
            raise ValueError(f"PCAP read error: {str(e)}")

    @staticmethod
    def live_capture(interface: str = None, 
                   packet_count: int = 100,
                   timeout: int = 30,
                   display_filter: str = None) -> List:
        """Capture live network traffic"""
        try:
            interface = interface or conf.iface
            console.print(f"\n[bold]Live capture on {interface}[/bold]")
            return sniff(iface=interface,
                       count=packet_count,
                       timeout=timeout,
                       filter=display_filter,
                       store=True)
        except Exception as e:
            raise ValueError(f"Live capture failed: {str(e)}")

    @staticmethod
    def estimate_packet_count(file_path: str) -> Union[int, str, None]:
        """Estimate packets in a PCAP file"""
        try:
            with ScapyPcapReader(str(file_path)) as pcap:
                return sum(1 for _ in pcap)
        except Exception:
            try:
                cap = pyshark.FileCapture(str(file_path), keep_packets=False)
                return sum(1 for _ in cap)
            except Exception:
                return None

# Create an alias for backward compatibility
PCAPReader = pcap_reader
