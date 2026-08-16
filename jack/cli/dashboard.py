"""Live progress dashboard using Rich Live."""

import time
import sys
from typing import Optional, Callable
from dataclasses import dataclass, field

try:
    from rich.console import Console
    from rich.layout import Layout
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich.live import Live
    from rich import box
    HAS_RICH = True
except ImportError:
    HAS_RICH = False


@dataclass
class DashboardState:
    """Real-time state for the dashboard."""
    target: str = ""
    format_detected: str = ""
    attack_mode: str = ""
    status: str = "idle"
    candidates_tested: int = 0
    matches_found: int = 0
    rate: float = 0.0
    start_time: float = 0.0
    last_match: str = ""
    last_match_time: float = 0.0
    hash_file: str = ""
    wordlist: str = ""
    error: str = ""
    
    @property
    def elapsed(self) -> float:
        if self.start_time > 0:
            return time.time() - self.start_time
        return 0.0
    
    @property
    def elapsed_str(self) -> str:
        return _fmt_time(self.elapsed)
    
    @property
    def rate_str(self) -> str:
        if self.rate >= 1_000_000:
            return f"{self.rate / 1_000_000:.2f} MH/s"
        elif self.rate >= 1_000:
            return f"{self.rate / 1_000:.2f} kH/s"
        return f"{self.rate:.0f} H/s"


def _fmt_time(seconds: float) -> str:
    h = int(seconds // 3600)
    m = int((seconds % 3600) // 60)
    s = int(seconds % 60)
    return f"{h:02d}:{m:02d}:{s:02d}"


def _make_bar(pct: float, width: int = 30) -> str:
    filled = int(width * min(pct, 100) / 100)
    return "\u2588" * filled + "\u2591" * (width - filled)


if HAS_RICH:
    class LiveDashboard:
        """Rich Live dashboard for real-time audit monitoring."""
        
        def __init__(self, state: DashboardState):
            self.state = state
            self.console = Console()
            self._live: Optional[Live] = None
        
        def _build_layout(self) -> Layout:
            layout = Layout()
            layout.split_column(
                Layout(name="header", size=3),
                Layout(name="body"),
                Layout(name="footer", size=3),
            )
            
            # Header
            header = Panel(
                Text("JACK THE RIPPER  |  Offline Password Audit Framework  |  v2.0.0",
                     justify="center", style="bold blue"),
                box=box.DOUBLE,
            )
            layout["header"].update(header)
            
            # Body split into left and right
            layout["body"].split_row(
                Layout(name="left", ratio=2),
                Layout(name="right", ratio=1),
            )
            
            # Left: progress
            bar = _make_bar(0)
            status_color = {"idle": "dim", "running": "green", "paused": "yellow",
                           "completed": "blue", "failed": "red"}.get(self.state.status, "dim")
            
            progress_text = Text()
            progress_text.append(f"Target       : {self.state.hash_file}\n", style="cyan")
            progress_text.append(f"Format       : {self.state.format_detected}\n", style="cyan")
            progress_text.append(f"Attack       : {self.state.attack_mode}\n", style="cyan")
            progress_text.append(f"Status       : {self.state.status.upper()}\n", style=status_color)
            progress_text.append(f"\nProgress     : {bar} 0.0%\n", style="green")
            progress_text.append(f"Tested       : {self.state.candidates_tested:,}\n", style="white")
            progress_text.append(f"Matches      : {self.state.matches_found}\n", style="bold green")
            progress_text.append(f"Rate         : {self.state.rate_str}\n", style="yellow")
            progress_text.append(f"Elapsed      : {self.state.elapsed_str}\n", style="white")
            
            layout["left"].update(Panel(progress_text, title="Audit Progress", border_style="green"))
            
            # Right: matches
            match_table = Table(box=box.SIMPLE, show_header=True, header_style="bold")
            match_table.add_column("#", style="dim", width=4)
            match_table.add_column("Password", style="bold green")
            match_table.add_column("Time", style="dim")
            
            if self.state.last_match:
                match_table.add_row("1", self.state.last_match,
                    _fmt_time(self.state.last_match_time - self.state.start_time) if self.state.start_time else "")
            
            layout["right"].update(Panel(match_table, title="Recent Matches", border_style="yellow"))
            
            # Footer
            footer_text = f"Session: {self.state.target}  |  Ctrl+C to pause  |  {self.state.elapsed_str} elapsed"
            layout["footer"].update(Panel(Text(footer_text, justify="center", style="dim"), border_style="dim"))
            
            return layout
        
        def start(self):
            if self._live is None:
                self._live = Live(self._build_layout(), console=self.console, refresh_per_second=4, screen=True)
                self._live.start()
        
        def update(self):
            if self._live:
                self._live.update(self._build_layout())
        
        def stop(self):
            if self._live:
                self._live.stop()
                self._live = None
        
        def __enter__(self):
            self.start()
            return self
        
        def __exit__(self, *args):
            self.stop()


class SimpleDashboard:
    """Fallback dashboard for terminals without Rich."""
    
    def __init__(self, state: DashboardState):
        self.state = state
        self._last_line = ""
    
    def start(self):
        print("Starting audit...")
    
    def update(self):
        bar = _make_bar(0, 20)
        line = (f"\r[{self.state.status}] Tested: {self.state.candidates_tested:,} | "
                f"Matches: {self.state.matches_found} | "
                f"Rate: {self.state.rate_str} | "
                f"Elapsed: {self.state.elapsed_str}")
        if line != self._last_line:
            sys.stdout.write(line + "   ")
            sys.stdout.flush()
            self._last_line = line
    
    def stop(self):
        print()
    
    def __enter__(self):
        self.start()
        return self
    
    def __exit__(self, *args):
        self.stop()


def create_dashboard(state: DashboardState):
    """Create the appropriate dashboard based on available libraries."""
    if HAS_RICH:
        return LiveDashboard(state)
    return SimpleDashboard(state)
