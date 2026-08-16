# Jack The Ripper (John The Ripper v2.0) ⚡

> **Advanced Offline Password Security Audit & Hash Analysis Framework**

[![Python Version](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)]()
[![Security Audit](https://img.shields.io/badge/security-audit--ready-red.svg)]()
[![Code Style: Ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)

**Jack The Ripper** (also known as *John the Ripper Python Edition*) is a high-performance, modular, offline password security audit framework built natively in Python 3.11+. Engineered for cybersecurity researchers, penetration testers, and security auditors, it provides multi-threaded attack engines, hardware acceleration detection, memory-mapped large wordlist streaming, intelligent pattern analysis, live terminal dashboards, and comprehensive enterprise PDF reporting.

---

## 🌟 Key Features & Architecture

### 🚀 1. Core Attack Engines (6 Modes)
- **Dictionary Attack**: Rapid wordlist streaming using memory-mapped (`mmap`) fast I/O.
- **Mask Attack**: Custom pattern expansion (`?u`, `?l`, `?d`, `?s`, `?a`, `?h`).
- **Rules Engine**: Advanced transformation rules (`l`ower, `u`pper, `c`apitalize, `r`everse, append/prepend) with custom `.rule` file parsing.
- **Hybrid Attack**: Combines dictionary bases with dynamic mask/suffix/prefix variations.
- **Pattern Attack**: Intelligent structural pattern generation based on statistical password topology.
- **Incremental Attack**: Smart brute-force mode with automatic length progression across configurable character sets.

### ⚡ 2. High-Performance Architecture
- **SIMD Hardware Acceleration**: Automatic CPU instruction detection (AVX2, AVX-512, SSE4.2).
- **Mmap Wordlist Streaming**: Ultra-fast line counting and random access for multi-gigabyte dictionary files without consuming memory.
- **Bloom Filter Candidate Deduplication**: Low-footprint in-memory set filtering to prevent candidate re-evaluation.
- **Process Pool Parallelization**: Multi-core CPU process scaling across all available physical & logical cores.

### 📊 3. Security Analytics & Intelligence
- **Password Strength Scoring**: Multi-metric entropy evaluation and strength categorization.
- **Pattern Analyzer**: Extracts common password structures, character distributions, and structural weaknesses.
- **Duplicate Detector**: Discovers reused password hashes across target sets.
- **Rule Learner**: Machine-learned rule recommendations based on cracked password patterns.
- **Rainbow Table Anomaly Detection**: Statistical chi-square and distribution analysis to flag pre-computed hash indicators.

### 🎨 4. Terminal UI & Session Control
- **Interactive Live Dashboard**: Rich-powered dashboard displaying live hash-rate ($H/s$), progress bars, estimated time to completion (ETA), and active worker statuses.
- **Stateful Sessions**: Pause, save, list, resume, or delete long-running audit jobs seamlessly.
- **Adaptive Rate Limiter**: Token-bucket and target-CPU rate limiting to prevent hardware thermal throttling.
- **Webhook Integration**: Real-time Slack, Discord, or custom webhook notifications for cracked hash alerts and audit milestones.

### 📑 5. Enterprise Reporting
- **Multi-Format Exports**: Export comprehensive audit reports in PDF (with visual charts), HTML, JSON, and CSV formats.

---

## 📂 Project Structure

```text
Jack-The-Ripper/
├── configs/               # System & attack configuration files
├── docs/                  # Architectural documentation & guides
├── examples/              # Sample targets, custom rules, & wordlists
├── john/                  # Core Python Package
│   ├── attacks/           # Attack implementations & rule engines
│   │   ├── base.py        # Base attack contract
│   │   ├── dictionary.py  # Dictionary attack engine
│   │   ├── incremental.py # Incremental brute-force generator
│   │   ├── mask.py        # Mask expansion attack
│   │   ├── ratelimit.py   # Rate limiting utilities
│   │   ├── ruleparser.py  # Rule file parser & evaluator
│   │   └── webhook.py     # Webhook notification engine
│   ├── candidates/        # Candidate generators & charsets
│   ├── cli/               # Typer/Rich CLI commands & dashboard UI
│   ├── core/              # Engine orchestration & multi-target managers
│   ├── hashes/            # Hash algorithms, identification & rainbow detection
│   ├── performance/       # SIMD detection, Mmap, Bloom filter, process pool
│   ├── plugins/           # Extensible plugin interfaces
│   ├── reporting/         # PDF, HTML, JSON, CSV reporting & scoring
│   ├── security/          # Input validation, auth & secure cleanup
│   └── storage/           # Session database & result persistence
├── rules/                 # Standard & comprehensive rule sets
├── tests/                 # Comprehensive Pytest suite & feature verification
├── wordlists/             # Default wordlists
└── pyproject.toml         # Package specification & entry points
```

---

## 💻 Installation

### Prerequisites
- **Python**: `>= 3.11`
- **Git**: Installed and configured

### 1. Clone the Repository
```bash
git clone https://github.com/HNS-06/Jack-The-Ripper.git
cd Jack-The-Ripper
```

### 2. Set Up Virtual Environment & Install
```bash
# Create virtual environment
python -m venv .venv

# Activate virtual environment
# Windows:
.venv\Scripts\activate
# Linux / macOS:
source .venv/bin/activate

# Upgrade pip and install package in editable mode
pip install --upgrade pip
pip install -e ".[dev]"
```

---

## 🛠️ CLI Quick Start & Usage

Once installed, the CLI tool `john` is available directly in your terminal:

```bash
john --help
```

### 1. Hash Format Identification
Auto-detect algorithm type, confidence score, and format breakdown:
```bash
john identify hashes.txt
```

### 2. Execute Password Audit (`audit` / `crack`)
Run a dictionary attack with transformation rules against target hashes:
```bash
john audit hashes.txt --wordlist wordlists/common.txt --rules rules/basic.txt
```

Run a mask attack for 6-digit PINs:
```bash
john audit hashes.txt --mode mask --mask "?d?d?d?d?d?d"
```

Run an incremental brute-force attack across alphanumeric characters:
```bash
john audit hashes.txt --mode incremental --charset alphanum --min-len 1 --max-len 6
```

### 3. Hardware Diagnostics & Benchmarks
Inspect CPU features (AVX2, SSE4.2), logical cores, and memory:
```bash
john hardware
```

Benchmark hash performance ($H/s$) across supported algorithms:
```bash
john benchmark
```

### 4. Multi-Target Cross-Reference Audit
Audit multiple hash sets simultaneously to discover shared credential leaks:
```bash
john multitarget target1.txt target2.txt
```

### 5. Session Management
List, resume, or clean up audit sessions:
```bash
# List active & saved sessions
john session-list

# Resume a paused session
john session-resume <session_id>

# Delete a session
john session-delete <session_id>
```

### 6. Environment Health Check
Validate installed dependencies, configuration files, and permissions:
```bash
john doctor
```

---

## 🧪 Verification & Testing

The project includes both a **Pytest unit test suite** and a **20-feature integration verification script**.

### Run Unit Tests
```bash
pytest
```

### Run Full 20-Feature Verification
```bash
python tests/verify_features.py
```

Expected Output:
```text
=== FEATURE VERIFICATION ===
[1] Incremental mode: OK
[2] Rate limiter: OK
[3] Charset generator: OK - 11110 candidates
[4] Rule parser: OK - 3 rules
[5] Live dashboard: OK
[6] Password Scorer: OK
[7] Pattern analyzer: OK - 3 insights
[8] Duplicate detector: OK - 1 groups
[9] Rule learner: OK - 2 suggestions
[10] Multi-target: OK
[11] Piped input: OK
[12] Process pool: OK
[13] Mmap wordlist: OK - 14 lines, 114 B
[14] Bloom filter: OK - 1.2 KB, has password=True
[15] Webhook notifier: OK
[16] SIMD detection: OK - AVX2=True
[17] PDF report: OK
[18] Rainbow detection: OK - 1 flagged
[19] CLI integration: OK
[20] Engine: OK - 6 attack modes: ['dictionary', 'mask', 'rules', 'hybrid', 'pattern', 'incremental']

=== ALL 20 FEATURES VERIFIED ===
```

---

## 🛡️ Security & Ethical Disclaimer

> **IMPORTANT**: This framework is developed strictly for **authorized security auditing, educational research, and defensive penetration testing**. Unauthorized password cracking against systems or networks without explicit written permission is strictly prohibited and illegal under applicable cybercrime laws.

---

## 📄 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.
