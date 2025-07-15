#!/usr/bin/env python3
import argparse
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, BarColumn, TimeRemainingColumn
from analyzers.flag_analyzer import FlagAnalyzer
from analyzers.protocol_stats import ProtocolStats
from analyzers.ioc_filter import IOCFilter
from utils.pcap_reader import PCAPReader
from utils.output_formatter import format_output, format_rich
from pathlib import Path
from typing import Optional

console = Console()

def print_banner():
    banner = r"""[bold blue]
   ___      _       _   ___       _      _     
  / _ \___ | | ___ | | / __|_ __| |_ __| |___ 
 / /_)/ _ \| |/ _ \| | \__ \ '_ \  _/ _` / -_)
/ ___/ (_) | | (_) | | |___/ . __/\__\__,_\___|
\/    \___/|_|\___/|_|     |_|                
    [/bold blue]"""
    console.print(Panel.fit(banner, title="PacketIntel", subtitle="PCAP Analysis Tool"))

# Modify the analyze_packets function:
def analyze_packets(packets, analyzers, progress, packet_count=None):
    """Perform analysis with progress tracking"""
    results = {}
    
    # Convert to list if not already
    if not isinstance(packets, list):
        packets = list(packets)
    
    with progress:
        task = progress.add_task("[cyan]Analyzing...", total=len(packets))
        
        for analyzer_name, analyzer in analyzers.items():
            # Create fresh iterator for each analyzer
            packets_iter = iter(packets)
            
            # Run analysis
            analyzer_results = analyzer.analyze(packets_iter)
            results[analyzer_name] = analyzer_results
            
            # Update progress
            progress.update(task, advance=len(packets)/len(analyzers))
                
    return results

def main():
    print_banner()
    
    parser = argparse.ArgumentParser(description="PacketIntel - PCAP Inspection Tool")
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument("--pcap", help="Path to PCAP file")
    input_group.add_argument("--live", action="store_true", help="Capture live traffic")
    
    parser.add_argument("--interface", default=None, help="Network interface (live mode)")
    parser.add_argument("--count", type=int, default=100, help="Packets to capture (live mode)")
    parser.add_argument("--timeout", type=int, default=30, help="Capture timeout in seconds (live mode)")
    parser.add_argument("--filter", 
                       choices=["suspicious", "protocols", "ioc", "all"], 
                       default="all",
                       help="Analysis filter type")
    parser.add_argument("--output", 
                       choices=["text", "json", "rich"], 
                       default="rich",
                       help="Output format")
    parser.add_argument("--bpf", default=None, help="BPF filter (live mode)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose output")
    
    args = parser.parse_args()

    try:
        # Initialize progress bar
        progress = Progress(
            BarColumn(),
            "[progress.percentage]{task.percentage:>3.0f}%",
            TimeRemainingColumn(),
            expand=True
        )

        # Packet capture
        if args.live:
            packets = PCAPReader.live_capture(
                interface=args.interface,
                packet_count=args.count,
                timeout=args.timeout,
                display_filter=args.bpf
            )
            packet_count = len(packets)
            console.print(f"\n📡 Captured [bold]{packet_count}[/bold] packets")
        else:
            # PCAP file analysis
            pcap_path = Path(args.pcap)
            if not pcap_path.exists():
                raise FileNotFoundError(f"PCAP file not found: {args.pcap}")
                
            with console.status("[bold green]Reading PCAP...[/bold green]"):
                packet_count = PCAPReader.estimate_packet_count(args.pcap)
                packets = PCAPReader.read_pcap(args.pcap)
                console.print(f"\n📦 Found [bold]{packet_count or 'unknown'}[/bold] packets")

        # Initialize analyzers
        analyzers = {}
        if args.filter == "all":
            analyzers = {
                "suspicious": FlagAnalyzer(),
                "protocols": ProtocolStats(),
                "ioc": IOCFilter()
            }
        else:
            if args.filter == "suspicious":
                analyzers["suspicious"] = FlagAnalyzer()
            elif args.filter == "protocols":
                analyzers["protocols"] = ProtocolStats()
            elif args.filter == "ioc":
                analyzers["ioc"] = IOCFilter()

        # Perform analysis
        results = analyze_packets(packets, analyzers, progress, packet_count)

        # Display results
        if args.output == "rich":
            format_rich(results)
        else:
            console.print(format_output(results, args.output))

    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")
        if args.verbose:
            import traceback
            console.print(traceback.format_exc())

if __name__ == "__main__":
    main()
