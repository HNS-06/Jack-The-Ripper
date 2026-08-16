"""Main CLI entry point for John the Ripper."""

import sys
import io
import time
import signal
import os
from pathlib import Path
from typing import Optional, List

# Fix Windows console encoding for Unicode output
if sys.platform == "win32":
    try:
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')
    except Exception:
        os.environ.setdefault('PYTHONIOENCODING', 'utf-8')

try:
    import typer
    from typer import Typer
except ImportError:
    print("Error: typer is required. Install with: pip install typer")
    sys.exit(1)

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich import print as rprint
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

from ..core.engine import AuditEngine, EngineConfig
from ..core.session import SessionManager
from ..hashes.detector import HashDetector


app = Typer(
    name="john",
    help="John the Ripper - Advanced Offline Password Audit Framework",
    no_args_is_help=True,
    add_completion=False,
)

console = Console() if HAS_RICH else None

BANNER = r"""
     ██╗ ██████╗ ██╗  ██╗███╗   ██╗
     ██║██╔═══██╗██║  ██║████╗  ██║
     ██║██║   ██║███████║██╔██╗ ██║
██   ██║██║   ██║██╔══██║██║╚██╗██║
╚█████╔╝╚██████╔╝██║  ██║██║ ╚████║
 ╚════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝

      T H E   R I P P E R
      Offline Password Audit Framework
      v2.0.0
"""

AUTH_WARNING = """
┌─ AUTHORIZED AUDIT ONLY ─────────────────────────┐
│ This tool operates on offline hash datasets.     │
│ Use only with explicit authorization.            │
│ Unauthorized access to systems is illegal.       │
└──────────────────────────────────────────────────┘
"""


def version_callback(value: bool):
    if value:
        print("John the Ripper v2.0.0")
        raise typer.Exit()


@app.callback()
def main(
    version: Optional[bool] = typer.Option(
        None, "--version", "-V", callback=version_callback,
        is_eager=True, help="Show version and exit"
    ),
):
    """John the Ripper - Advanced Offline Password Audit Framework"""
    pass


# ── IDENTIFY ──────────────────────────────────────────────────────────────

@app.command()
def identify(
    hash_file: str = typer.Argument(..., help="Path to hash file"),
    format: Optional[str] = typer.Option(None, "--format", "-f", help="Force hash format"),
):
    """Identify hash formats in a file."""
    if not Path(hash_file).exists():
        print(f"Error: File not found: {hash_file}")
        raise typer.Exit(1)

    engine = AuditEngine()
    if console:
        console.print(Panel(f"[bold]Hash Identification[/bold]\nFile: {hash_file}", title="JOHN"))
        result = engine.detect(hash_file)
        table = Table(title="Detection Results")
        table.add_column("Format", style="cyan")
        table.add_column("Count", justify="right", style="green")
        table.add_column("Confidence", justify="right", style="yellow")
        for fmt, count in sorted(result.format_breakdown.items(), key=lambda x: x[1], reverse=True):
            conf = result.confidence.get(fmt, 0)
            table.add_row(fmt, str(count), f"{conf:.2f}")
        if result.unknown_count:
            table.add_row("[red]Unknown[/red]", str(result.unknown_count), "-")
        console.print(table)
        console.print(f"\nTotal: {result.valid_hashes} valid hashes detected")
    else:
        print(engine.identify(hash_file))


# ── AUDIT ─────────────────────────────────────────────────────────────────

@app.command()
def audit(
    hash_file: str = typer.Argument(..., help="Path to hash file"),
    mode: str = typer.Option("dictionary", "--mode", "-m", help="Attack mode"),
    wordlist: Optional[str] = typer.Option(None, "--wordlist", "-w", help="Wordlist file"),
    mask: Optional[str] = typer.Option(None, "--mask", help="Mask pattern"),
    rules: Optional[str] = typer.Option(None, "--rules", "-r", help="Rules preset or file"),
    format: Optional[str] = typer.Option(None, "--format", "-f", help="Force hash format"),
    max_candidates: Optional[int] = typer.Option(None, "--max-candidates", help="Max candidates"),
    max_time: Optional[int] = typer.Option(None, "--max-time", "-t", help="Max time (seconds)"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output file"),
    rate_limit: int = typer.Option(0, "--rate", help="Rate limit (candidates/sec, 0=unlimited)"),
    charset: Optional[str] = typer.Option(None, "--charset", help="Charset for incremental mode"),
    min_length: int = typer.Option(1, "--min-length", help="Min candidate length"),
    max_length: int = typer.Option(8, "--max-length", help="Max candidate length"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
    webhook: Optional[str] = typer.Option(None, "--webhook", help="Webhook URL for notifications"),
    live: bool = typer.Option(False, "--live", help="Enable live dashboard"),
):
    """Run an offline password audit."""
    print(AUTH_WARNING)

    if not Path(hash_file).exists():
        print(f"Error: File not found: {hash_file}")
        raise typer.Exit(1)

    if mode in ("dictionary", "rules", "hybrid") and not wordlist:
        print(f"Error: --wordlist required for {mode} mode")
        raise typer.Exit(1)
    if mode == "mask" and not mask:
        print("Error: --mask required for mask mode")
        raise typer.Exit(1)

    config = EngineConfig(
        hash_file=hash_file,
        attack_mode=mode,
        wordlist=wordlist,
        mask=mask,
        rules=rules,
        format_override=format,
        max_candidates=max_candidates,
        max_time=max_time,
        rate_limit=rate_limit,
        charset=charset,
        min_length=min_length,
        max_length=max_length,
    )

    engine = AuditEngine()
    session_mgr = SessionManager()
    session = session_mgr.create(config={"hash_file": hash_file, "mode": mode, "wordlist": wordlist, "mask": mask})

    if console:
        console.print(Panel(f"[bold]Password Audit[/bold]\nTarget: {hash_file}\nMode: {mode}", title="JOHN"))

    def signal_handler(sig, frame):
        print("\n\nInterrupted! Saving session...")
        session_mgr.pause(session)
        print(f"Session saved: {session.session_id}")
        print(f"Resume with: john session-resume {session.session_id}")
        raise typer.Exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    # Setup webhook
    wh_notifier = None
    if webhook:
        try:
            from ..attacks.webhook import WebhookNotifier, WebhookConfig
            wh_notifier = WebhookNotifier([WebhookConfig(url=webhook)])
            wh_notifier.start()
        except Exception:
            pass

    # Setup live dashboard
    dashboard = None
    if live:
        try:
            from ..cli.dashboard import DashboardState, create_dashboard
            dash_state = DashboardState(
                target=hash_file, format_detected=format or "auto",
                attack_mode=mode, status="running", hash_file=hash_file,
                wordlist=wordlist or "", start_time=time.time(),
            )
            dashboard = create_dashboard(dash_state)
            dashboard.start()
        except Exception:
            pass

    try:
        session.status = "running"
        session.started_at = time.time()
        session_mgr.update(session)

        # Progress callback
        last_update = [0.0]
        def on_progress(tested, matches):
            now = time.time()
            if now - last_update[0] < 0.25:
                return
            last_update[0] = now
            if dashboard:
                dash_state.candidates_tested = tested
                dash_state.matches_found = matches
                if session.started_at:
                    elapsed = now - session.started_at
                    dash_state.rate = tested / elapsed if elapsed > 0 else 0
                dashboard.update()

        engine.set_progress_callback(on_progress)

        # Match callback for webhook
        if wh_notifier:
            def on_match_webhook(result):
                wh_notifier.notify_match(
                    result.candidate, result.hash_value,
                    result.format_name, result.strategy, session.session_id
                )
            engine.set_match_callback(on_match_webhook)

        result = engine.audit(config)

        # Stop dashboard
        if dashboard:
            dash_state.status = "completed"
            dashboard.update()
            time.sleep(0.5)
            dashboard.stop()

        # Complete session
        session.completed_at = time.time()
        for match in result.matches:
            session_mgr.add_match(session, match)
        session_mgr.complete(session)

        # Webhook completion
        if wh_notifier:
            wh_notifier.notify_complete(
                session.session_id, result.attack_stats.total_tested,
                result.match_count, result.elapsed
            )
            wh_notifier.stop()

        # Print results
        if console:
            table = Table(title="Audit Results")
            table.add_column("Metric", style="cyan")
            table.add_column("Value", style="green")
            table.add_row("Status", "Completed" if result.success else "No matches")
            table.add_row("Candidates Tested", f"{result.attack_stats.total_tested:,}")
            table.add_row("Matches Found", str(result.match_count))
            table.add_row("Speed", f"{result.attack_stats.rate:,.1f} H/s")
            table.add_row("Elapsed", f"{result.elapsed:.2f}s")
            console.print(table)

            if result.matches:
                match_table = Table(title="Matches Found")
                match_table.add_column("#", style="dim")
                match_table.add_column("Password", style="bold green")
                match_table.add_column("Hash", style="cyan")
                match_table.add_column("Format")
                for i, match in enumerate(result.matches, 1):
                    match_table.add_row(str(i), match.candidate,
                        match.hash_value[:20] + "...", match.format_name)
                console.print(match_table)

            # Print scoring if available
            if result.scored_passwords:
                score_table = Table(title="Password Strength Scores")
                score_table.add_column("Password", style="bold")
                score_table.add_column("Score", justify="right")
                score_table.add_column("Strength")
                score_table.add_column("Category")
                for ps in result.scored_passwords[:20]:
                    color = {"very_weak": "red", "weak": "red", "moderate": "yellow",
                            "strong": "green", "very_strong": "blue"}.get(ps.strength, "dim")
                    score_table.add_row(ps.password, str(ps.score),
                        f"[{color}]{ps.strength}[/{color}]", ps.category)
                console.print(score_table)

            # Print pattern insights
            if result.pattern_insights:
                insight_table = Table(title="Pattern Analysis")
                insight_table.add_column("Pattern", style="cyan")
                insight_table.add_column("Count", justify="right")
                insight_table.add_column("Risk")
                insight_table.add_column("Examples", max_width=40)
                for insight in result.pattern_insights[:10]:
                    risk_color = {"critical": "red", "high": "red", "medium": "yellow", "low": "dim"}.get(insight.risk_level, "dim")
                    examples = ", ".join(insight.examples[:3])
                    insight_table.add_row(insight.pattern_type, str(insight.count),
                        f"[{risk_color}]{insight.risk_level}[/{risk_color}]", examples)
                console.print(insight_table)

            # Print duplicate groups
            if result.duplicate_groups:
                dup_table = Table(title="Password Reuse Detection")
                dup_table.add_column("Reuse Count", justify="right", style="red")
                dup_table.add_column("Affected Hashes", justify="right")
                for dg in result.duplicate_groups[:10]:
                    dup_table.add_row(str(dg.count), str(len(dg.hash_values)))
                console.print(dup_table)

            # Print rule suggestions
            if result.rule_suggestions:
                rule_text = "\n".join(f"  [{r['priority']}] {r['rule']}: {r['reason']}" for r in result.rule_suggestions[:10])
                console.print(Panel(rule_text, title="Suggested Rules for Unrecovered Hashes"))
        else:
            print(f"\nAudit Complete")
            print(f"Candidates tested: {result.attack_stats.total_tested:,}")
            print(f"Matches: {result.match_count}")
            print(f"Speed: {result.attack_stats.rate:,.1f} H/s")
            for match in result.matches:
                print(f"  {match.candidate} ({match.format_name})")

        if output:
            _save_results(output, result, session.session_id)
            print(f"\nResults saved to: {output}")

    except Exception as e:
        if dashboard:
            dashboard.stop()
        if wh_notifier:
            wh_notifier.notify_error(str(e), session.session_id)
            wh_notifier.stop()
        session.status = "failed"
        session.error = str(e)
        session_mgr.update(session)
        print(f"\nError: {e}")
        raise typer.Exit(1)


# ── CRACK (alias) ────────────────────────────────────────────────────────

@app.command()
def crack(
    hash_file: str = typer.Argument(..., help="Path to hash file"),
    mode: str = typer.Option("dictionary", "--mode", "-m"),
    wordlist: Optional[str] = typer.Option(None, "--wordlist", "-w"),
    mask: Optional[str] = typer.Option(None, "--mask"),
    rules: Optional[str] = typer.Option(None, "--rules", "-r"),
    format: Optional[str] = typer.Option(None, "--format", "-f"),
):
    """Crack passwords (alias for audit)."""
    audit(hash_file, mode, wordlist, mask, rules, format)


# ── BENCHMARK ─────────────────────────────────────────────────────────────

@app.command()
def benchmark(
    duration: int = typer.Option(3, "--duration", "-d", help="Duration in seconds"),
    format: Optional[str] = typer.Option(None, "--format", "-f", help="Specific format"),
):
    """Benchmark hash algorithms."""
    print(BANNER)
    print("\nRunning benchmark...\n")

    engine = AuditEngine()
    formats = engine.list_formats()

    if console:
        table = Table(title="Benchmark Results")
        table.add_column("Algorithm", style="cyan")
        table.add_column("Speed", justify="right", style="green")
        table.add_column("Time", justify="right")
        for fmt_info in formats:
            algo = engine.registry.get(fmt_info['id'])
            if algo and (not format or fmt_info['id'] == format):
                speed = _benchmark_algo(algo, duration)
                table.add_row(fmt_info['name'], f"{speed:,.1f} H/s", f"{duration}s")
        console.print(table)
    else:
        for fmt_info in formats:
            algo = engine.registry.get(fmt_info['id'])
            if algo and (not format or fmt_info['id'] == format):
                speed = _benchmark_algo(algo, duration)
                print(f"{fmt_info['name']:15s} {speed:>10,.1f} H/s")


# ── SESSION COMMANDS ──────────────────────────────────────────────────────

@app.command()
def session_list(
    limit: int = typer.Option(20, "--limit", "-l"),
):
    """List audit sessions."""
    mgr = SessionManager()
    sessions = mgr.list_sessions(limit)
    if console:
        table = Table(title="Sessions")
        table.add_column("Session ID", style="cyan")
        table.add_column("Status")
        table.add_column("Mode")
        table.add_column("Matches", justify="right")
        table.add_column("Created")
        for s in sessions:
            status_style = {"completed": "green", "running": "yellow", "paused": "blue", "failed": "red"}.get(s.status, "dim")
            table.add_row(s.session_id, f"[{status_style}]{s.status}[/{status_style}]",
                s.attack_mode, str(s.matches_found),
                time.strftime("%Y-%m-%d %H:%M", time.localtime(s.created_at)))
        console.print(table)
    else:
        for s in sessions:
            print(f"{s.session_id:30s} {s.status:10s} {s.attack_mode:12s} {s.matches_found:5d}")


@app.command()
def session_resume(
    session_id: str = typer.Argument(..., help="Session ID to resume"),
):
    """Resume a paused session."""
    mgr = SessionManager()
    session = mgr.get(session_id)
    if not session:
        print(f"Session not found: {session_id}")
        raise typer.Exit(1)
    if session.status != "paused":
        print(f"Session is not paused (status: {session.status})")
        raise typer.Exit(1)
    print(f"Resuming session: {session_id}")
    print(f"Config: {session.config}")


@app.command()
def session_delete(
    session_id: str = typer.Argument(..., help="Session ID to delete"),
):
    """Delete a session."""
    mgr = SessionManager()
    mgr.delete(session_id)
    print(f"Session deleted: {session_id}")


# ── FORMATS ───────────────────────────────────────────────────────────────

@app.command()
def formats():
    """List supported hash formats."""
    engine = AuditEngine()
    fmts = engine.list_formats()
    if console:
        table = Table(title="Supported Hash Formats")
        table.add_column("ID", style="cyan")
        table.add_column("Name", style="green")
        table.add_column("Hash Length", justify="right")
        table.add_column("Patterns", justify="right")
        for f in fmts:
            table.add_row(f['id'], f['name'], str(f['hash_length']), str(f['patterns']))
        console.print(table)
    else:
        for f in fmts:
            print(f"{f['id']:15s} {f['name']:15s} len={f['hash_length']:3d}  patterns={f['patterns']}")


# ── ATTACKS ───────────────────────────────────────────────────────────────

@app.command()
def attacks():
    """List available attack modes."""
    engine = AuditEngine()
    atts = engine.list_attacks()
    if console:
        table = Table(title="Attack Modes")
        table.add_column("Mode", style="cyan")
        table.add_column("Class", style="green")
        table.add_column("Description")
        for a in atts:
            table.add_row(a['name'], a['class'], a['description'])
        console.print(table)
    else:
        for a in atts:
            print(f"{a['name']:15s} {a['class']:25s} {a['description']}")


# ── WORDLISTS ─────────────────────────────────────────────────────────────

@app.command()
def wordlists():
    """Manage wordlists."""
    wl_dir = Path("wordlists")
    if wl_dir.exists():
        files = list(wl_dir.glob("*.txt"))
        if files:
            print("Available wordlists:")
            for f in sorted(files):
                count = sum(1 for _ in open(f, 'r', errors='ignore'))
                print(f"  {f.name:30s} {count:>8,} words")
        else:
            print("No wordlists found in wordlists/")
    else:
        print("wordlists/ directory not found")


# ── RULES ─────────────────────────────────────────────────────────────────

@app.command()
def rules_list():
    """List available transformation rules."""
    from ..attacks.rules import RuleEngine
    engine = RuleEngine()
    presets = engine.list_presets()
    print("Available rule presets:")
    for preset in presets:
        print(f"  {preset}")
    print("\nIndividual operations:")
    from ..candidates.mutations import MutationEngine
    ops = [m for m in dir(MutationEngine) if not m.startswith('_') and callable(getattr(MutationEngine, m))]
    for op in ops:
        print(f"  {op}")


@app.command()
def rules_parse(
    rule_file: str = typer.Argument(..., help="Path to .rule file"),
):
    """Parse and display a .rule file."""
    from ..attacks.ruleparser import RuleFileParser
    parser = RuleFileParser()
    try:
        rules = parser.parse_file(rule_file)
        print(f"Parsed {len(rules)} rules from {rule_file}")
        for i, chain in enumerate(rules[:20], 1):
            ops = " ".join(f"{op.code}{' ' + op.args if op.args else ''}" for op in chain)
            print(f"  {i:3d}: {ops}")
        if len(rules) > 20:
            print(f"  ... and {len(rules) - 20} more rules")
    except Exception as e:
        print(f"Error parsing rules: {e}")


# ── HARDWARE ──────────────────────────────────────────────────────────────

@app.command()
def hardware():
    """Show hardware capabilities (CPU, SIMD)."""
    from ..performance.simd import get_hardware_summary
    info = get_hardware_summary()

    if console:
        table = Table(title="Hardware Capabilities")
        table.add_column("Feature", style="cyan")
        table.add_column("Value", style="green")
        for k, v in info.get("cpu", {}).items():
            table.add_row(f"CPU {k}", str(v))
        for k, v in info.get("simd", {}).items():
            style = "green" if v else "dim"
            table.add_row(f"SIMD {k}", f"[{style}]{v}[/{style}]")
        for k, v in info.get("platform", {}).items():
            table.add_row(f"Platform {k}", str(v))
        console.print(table)
    else:
        for section, data in info.items():
            print(f"\n{section.upper()}:")
            for k, v in data.items():
                print(f"  {k}: {v}")


# ── MULTI-TARGET ──────────────────────────────────────────────────────────

@app.command()
def multitarget(
    hash_files: List[str] = typer.Argument(..., help="Hash files to combine"),
    format: Optional[str] = typer.Option(None, "--format", "-f"),
    mode: str = typer.Option("dictionary", "--mode", "-m"),
    wordlist: Optional[str] = typer.Option(None, "--wordlist", "-w"),
):
    """Audit multiple hash files (cross-reference mode)."""
    print(AUTH_WARNING)
    from ..core.multitarget import MultiTargetManager, MultiTargetConfig

    mt_config = MultiTargetConfig(hash_files=hash_files, combine=True, format_override=format)
    mt_mgr = MultiTargetManager()
    mt_mgr.load_targets(mt_config)

    print(f"\nLoaded {mt_mgr.total_targets} targets, {mt_mgr.total_hashes} total hashes")
    print(f"Format distribution: {mt_mgr.get_format_summary()}")

    common = mt_mgr.find_common_hashes()
    if common:
        print(f"\nFound {len(common)} hashes appearing in multiple targets!")
        for h, files in list(common.items())[:5]:
            print(f"  {h[:20]}... in {len(files)} files")

    if wordlist:
        config = EngineConfig(
            hash_file=hash_files[0],
            hash_files=hash_files,
            attack_mode=mode,
            wordlist=wordlist,
            format_override=format,
        )
        engine = AuditEngine()
        result = engine.audit(config)
        print(f"\nAudit: {result.attack_stats.total_tested:,} tested, {result.match_count} matches")


# ── DOCTOR ────────────────────────────────────────────────────────────────

@app.command()
def doctor():
    """Diagnose installation and environment."""
    print(BANNER)
    print("\nJOHN SYSTEM DIAGNOSTICS")
    print("=" * 50)

    checks = []
    checks.append(("Python runtime", True, f"Python {sys.version.split()[0]}"))

    deps = {"typer": "typer", "rich": "rich", "pyyaml": "yaml", "pydantic": "pydantic", "jinja2": "jinja2"}
    for name, module in deps.items():
        try:
            __import__(module)
            checks.append((f"Dependency: {name}", True, "installed"))
        except ImportError:
            checks.append((f"Dependency: {name}", False, "not installed"))

    cpu_count = os.cpu_count() or 1
    checks.append(("CPU detection", True, f"{cpu_count} cores"))

    import hashlib
    try:
        hashlib.md5(b"test")
        checks.append(("Hash library", True, "working"))
    except Exception:
        checks.append(("Hash library", False, "error"))

    session_dir = Path.home() / ".john" / "sessions"
    checks.append(("Session storage", True, str(session_dir)))

    # SIMD detection
    try:
        from ..performance.simd import detect_simd
        simd = detect_simd()
        checks.append(("SIMD/AVX", True, f"AVX2={simd.avx2}, AES-NI={simd.aes_ni}"))
    except Exception:
        checks.append(("SIMD/AVX", False, "detection failed"))

    all_ok = True
    for name, ok, detail in checks:
        glyph = "[green][+][/green]" if ok else "[red][x][/red]" if HAS_RICH else ("[OK]" if ok else "[!!]")
        status = f"{glyph} {name}"
        if detail:
            status += f" - {detail}"
        print(f"  {status}")
        if not ok:
            all_ok = False

    print()
    if all_ok:
        print("System ready.")
    else:
        print("Some checks failed. Install missing dependencies.")


# ── CONFIG ────────────────────────────────────────────────────────────────

@app.command()
def config_show():
    """Show current configuration."""
    config_dir = Path.home() / ".john"
    print(f"Config directory: {config_dir}")
    config_file = config_dir / "config.toml"
    if config_file.exists():
        print(f"\nConfig file: {config_file}")
        print(config_file.read_text())
    else:
        print("\nNo config file found. Using defaults.")


# ── HELPERS ───────────────────────────────────────────────────────────────

def _benchmark_algo(algo, duration: int) -> float:
    candidate_sample = "benchmark_sample"
    start = time.time()
    count = 0
    while time.time() - start < duration:
        try:
            algo.hash(candidate_sample)
            count += 1
        except Exception:
            break
    elapsed = time.time() - start
    return count / elapsed if elapsed > 0 else 0


def _save_results(output: str, result, session_id: str = ""):
    import json
    data = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "session_id": session_id,
        "config": {"hash_file": result.config.hash_file, "attack_mode": result.config.attack_mode},
        "stats": {
            "candidates_tested": result.attack_stats.total_tested,
            "matches": result.match_count,
            "speed": result.attack_stats.rate,
            "elapsed": result.elapsed,
        },
        "matches": [m.to_dict() for m in result.matches],
        "scores": [s.to_dict() for s in result.scored_passwords] if result.scored_passwords else [],
        "patterns": [p.to_dict() for p in result.pattern_insights] if result.pattern_insights else [],
        "duplicates": [d.to_dict() for d in result.duplicate_groups] if result.duplicate_groups else [],
        "rule_suggestions": result.rule_suggestions if result.rule_suggestions else [],
    }
    Path(output).write_text(json.dumps(data, indent=2))


def cli():
    """CLI entry point."""
    app()


if __name__ == "__main__":
    cli()
