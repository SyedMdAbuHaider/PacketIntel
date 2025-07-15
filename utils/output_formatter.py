from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.box import ROUNDED
import json
from typing import Dict, Any

console = Console()

def format_output(results: Dict[str, Any], format_type: str = "text") -> str:
    """
    Format analysis results based on requested output type
    
    Args:
        results: Dictionary containing analysis results
        format_type: One of 'text', 'json', or 'rich'
    
    Returns:
        Formatted output string
    """
    if format_type == "json":
        return json.dumps(results, indent=2)
    elif format_type == "rich":
        return format_rich(results)
    else:
        return format_text(results)

def format_rich(results: Dict[str, Any]) -> str:
    """
    Format results using Rich library for beautiful console output
    
    Args:
        results: Dictionary containing analysis results
        
    Returns:
        Empty string (output is printed directly to console)
    """
    # Main results table
    main_table = Table(title="PacketIntel Analysis Results", 
                      box=ROUNDED,
                      show_header=True, 
                      header_style="bold magenta")
    main_table.add_column("Category", style="cyan")
    main_table.add_column("Findings", style="green")
    
    # Suspicious Flags Analysis
    if 'suspicious' in results:
        sus = results['suspicious']
        syn_text = "\n".join([f"{ip}: {count}" for ip, count in sus.get('syn_scans', {}).items()]) or "None"
        malformed = sus.get('malformed_packets', 0)
        main_table.add_row(
            "Suspicious Flags",
            f"SYN Scans:\n{syn_text}\nMalformed Packets: {malformed}"
        )
    
    # Protocol Distribution
    if 'protocols' in results:
        protocols = results['protocols']
        if protocols:
            total = sum(protocols.values())
            proto_text = "\n".join(
                f"{proto}: {count} ({count/total:.1%})" 
                for proto, count in protocols.items()
            )
            main_table.add_row("Protocol Distribution", proto_text)
        else:
            main_table.add_row("Protocol Distribution", "No protocols identified")
    
    # Malicious Indicators
    if 'ioc' in results:
        iocs = results['ioc']
        ioc_text = "\n".join(iocs) if iocs else "No known IOCs found"
        main_table.add_row("Malicious Indicators", ioc_text)
    
    console.print(main_table)
    return ""

def format_text(results: Dict[str, Any]) -> str:
    """
    Format results as plain text
    
    Args:
        results: Dictionary containing analysis results
        
    Returns:
        Plain text formatted string
    """
    output = []
    
    if 'suspicious' in results:
        output.append("\n=== Suspicious Flag Analysis ===")
        sus = results['suspicious']
        if sus.get('syn_scans'):
            output.append("\nSYN Scans Detected:")
            for ip, count in sus['syn_scans'].items():
                output.append(f"  {ip}: {count} attempts")
        else:
            output.append("\nNo SYN scans detected")
        output.append(f"Malformed packets: {sus.get('malformed_packets', 0)}")
    
    if 'protocols' in results:
        output.append("\n=== Protocol Distribution ===")
        protocols = results['protocols']
        total = sum(protocols.values())
        for proto, count in protocols.items():
            output.append(f"{proto}: {count} ({count/total:.1%})")
    
    if 'ioc' in results:
        output.append("\n=== Malicious Indicators ===")
        iocs = results['ioc']
        if iocs:
            for match in iocs:
                output.append(f"- {match}")
        else:
            output.append("No known malicious indicators found")
    
    return "\n".join(output)
