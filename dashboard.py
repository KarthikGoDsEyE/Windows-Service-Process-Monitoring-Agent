from rich.table import Table
from rich.console import Console
from rich import box

console = Console()

def truncate_path_left(path, max_length=55):
    """Truncates paths from the left so the .exe name is always visible"""
    if path and len(path) > max_length:
        return "..." + path[-(max_length - 3):]
    return path

def generate_table(data, mode):
    # Calculate Summary Stats for the header
    safe = sum(1 for item in data if item.get("severity") == "SAFE")
    low = sum(1 for item in data if item.get("severity") == "LOW")
    medium = sum(1 for item in data if item.get("severity") == "MEDIUM")
    high = sum(1 for item in data if item.get("severity") in ["HIGH", "MALICIOUS"])

    # Format the header with the new colors
    header_text = (
        "Windows EDR - Monitor\n"
        f"Mode: {mode}\n\n"
        f"[bold green]SAFE: {safe}[/bold green] | [bold blue]LOW: {low}[/bold blue] | "
        f"[bold yellow]MEDIUM: {medium}[/bold yellow] | [bold red]HIGH: {high}[/bold red]"
    )

    # Initialize the Table with a Bottom Caption
    table = Table(
        title=header_text,
        title_justify="center",
        caption="\n[bold cyan]Press[/bold cyan] [bold yellow]Q[/bold yellow] [bold cyan]to terminate monitoring.[/bold cyan]", # 🔥 Added the Q to quit instruction here
        caption_justify="center",
        box=box.SQUARE,
        show_header=True,
        header_style="bold white",
        expand=True
    )

    # Define Columns
    table.add_column("Status", justify="center", width=6)
    table.add_column("Process", justify="left", no_wrap=True, max_width=30)
    table.add_column("PID", justify="left", no_wrap=True, max_width=8)
    table.add_column("Publisher", justify="left", no_wrap=True, max_width=25)
    table.add_column("Connection", justify="left", no_wrap=True, max_width=35)
    table.add_column("Path", justify="left", no_wrap=True)

    # Display ALL rows
    for item in data:
        severity = item.get("severity", "UNKNOWN")
        is_new = item.get("is_new", False)
        
        # Color-coded dots
        if severity in ["HIGH", "MALICIOUS"]:
            status_icon = "[bold red]●[/bold red]"
        elif severity == "MEDIUM":
            status_icon = "[bold yellow]●[/bold yellow]"
        elif severity == "LOW":
            status_icon = "[bold blue]●[/bold blue]"
        elif severity == "SAFE":
            status_icon = "[bold green]●[/bold green]"
        else:
            status_icon = "[white]○[/white]"

        # Fallback values to prevent errors
        process_name = item.get("name", "Unknown")
        pid_str = str(item.get("pid", ""))
        
        publisher = item.get("publisher", "N/A")
        if not publisher: publisher = "N/A"
        
        connection = item.get("connection", "No Network")
        if not connection: connection = "No Network"
        
        path = item.get("path", "Access Denied")
        if not path: path = "Access Denied"

        # HIGHLIGHT NEW PROCESSES
        if is_new:
            row_style = "bold white"
            process_name = f"[NEW] {process_name}"
        else:
            row_style = "cyan"

        # Add row
        table.add_row(
            status_icon,
            f"[{row_style}]{process_name}[/{row_style}]",
            f"[{row_style}]{pid_str}[/{row_style}]",
            f"[{row_style}]{publisher}[/{row_style}]",
            f"[{row_style}]{connection}[/{row_style}]",
            f"[{row_style}]{truncate_path_left(path, 60)}[/{row_style}]"
        )

    return table

def show_dashboard(data, mode):
    return generate_table(data, mode)