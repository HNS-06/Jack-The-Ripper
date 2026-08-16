"""Terminal UI components using Rich."""

from typing import Optional, List
import time

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeRemainingColumn
    from rich.layout import Layout
    from rich.text import Text
    from rich.live import Live
    HAS_RICH = True
except ImportError:
    HAS_RICH = False


class AuditDashboard:
    """Real-time audit dashboard."""
    
    def __init__(self):
        if not HAS_RICH:
            raise RuntimeError("Rich library required for dashboard")
        self.console = Console()
        self._start_time = 0
        self._stats = {}
    
    def create_layout(self) -> Layout:
        """Create the dashboard layout."""
        layout = Layout()
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="body"),
            Layout(name="footer", size=3),
        )
        return layout
    
    def render_header(self, target: str, mode: str, fmt: str) -> Panel:
        """Render header panel."""
        return Panel(
            f"[bold]JACK THE RIPPER[/bold]\n"
            f"Target: {target}  |  Format: {fmt}  |  Mode: {mode}",
            title="Audit Dashboard",
            border_style="blue",
        )
    
    def render_progress(
        self,
        tested: int,
        matches: int,
        rate: float,
        progress_pct: float,
        elapsed: float,
    ) -> Panel:
        """Render progress panel."""
        bar_width = 30
        filled = int(bar_width * progress_pct / 100)
        bar = "█" * filled + "░" * (bar_width - filled)
        
        content = (
            f"Progress     : {bar} {progress_pct:.1f}%\n"
            f"Tested       : {tested:,}\n"
            f"Matches      : {matches}\n"
            f"Rate         : {rate:,.1f} H/s\n"
            f"Elapsed      : {self._format_time(elapsed)}"
        )
        
        return Panel(content, title="Progress", border_style="green")
    
    def render_stats(self, stats: dict) -> Panel:
        """Render statistics panel."""
        content = "\n".join(f"{k:15s}: {v}" for k, v in stats.items())
        return Panel(content, title="Statistics", border_style="yellow")
    
    def _format_time(self, seconds: float) -> str:
        """Format seconds to HH:MM:SS."""
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        secs = int(seconds % 60)
        return f"{hours:02d}:{minutes:02d}:{secs:02d}"


def print_banner():
    """Print the Jack the Ripper banner."""
    banner = r"""
   ██████╗ █████╗  ██████╗██╗  ██╗
   ██╔════╝██╔══██╗██╔════╝██║ ██╔╝
   ██║     ███████║██║     █████═╝ 
   ██║     ██╔══██║██║     ██╔═██╗ 
   ╚██████╗██║  ██║╚██████╗██║  ██╗
    ╚═════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═══╝

      T H E   R I P P E R
      Offline Password Audit Framework
      v2.0.0
"""
    if HAS_RICH:
        console = Console()
        console.print(Panel(banner.strip(), border_style="blue"))
    else:
        print(banner)


def print_section(title: str, content: str):
    """Print a formatted section."""
    if HAS_RICH:
        Console().print(Panel(content, title=title))
    else:
        print(f"\n{title}")
        print("=" * len(title))
        print(content)


def print_table(title: str, headers: List[str], rows: List[List[str]]):
    """Print a formatted table."""
    if HAS_RICH:
        table = Table(title=title)
        for header in headers:
            table.add_column(header)
        for row in rows:
            table.add_row(*row)
        Console().print(table)
    else:
        print(f"\n{title}")
        print("-" * 60)
        header_line = "  ".join(f"{h:15s}" for h in headers)
        print(header_line)
        print("-" * 60)
        for row in rows:
            print("  ".join(f"{c:15s}" for c in row))
