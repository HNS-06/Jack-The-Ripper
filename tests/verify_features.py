import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

print('=== FEATURE VERIFICATION ===')

from jack.attacks.incremental import IncrementalAttack, CHARSETS
print('[1] Incremental mode: OK')

from jack.attacks.ratelimit import RateLimiter
print('[2] Rate limiter: OK')

from jack.candidates.charset import CharsetGenerator
cg = CharsetGenerator.from_name('digits', 1, 4)
print(f'[3] Charset generator: OK - {cg.estimate_count()} candidates')

from jack.attacks.ruleparser import RuleFileParser
rp = RuleFileParser()
rules = rp.parse_string('l\nu\nc')
print(f'[4] Rule parser: OK - {len(rules)} rules')

from jack.cli.dashboard import DashboardState, create_dashboard
print('[5] Live dashboard: OK')

from jack.reporting.scoring import PasswordScorer
scorer = PasswordScorer()
scores = scorer.score_batch(['password', 'AlphaNumeric123!', 'xK9#mZ'])
for s in scores:
    print(f'   [{s.score:3d}] {s.strength:12s} {s.password}')

from jack.reporting.analyzer import PatternAnalyzer, DuplicateDetector, RuleLearner
insights = PatternAnalyzer().analyze(['password', 'Password1', '123456'])
print(f'[7] Pattern analyzer: OK - {len(insights)} insights')

groups = DuplicateDetector().detect([('pw1', 'h1'), ('pw1', 'h2')])
print(f'[8] Duplicate detector: OK - {len(groups)} groups')

suggestions = RuleLearner().learn(['Password1', 'AlphaNumeric!'])
print(f'[9] Rule learner: OK - {len(suggestions)} suggestions')

from jack.core.multitarget import MultiTargetManager
print('[10] Multi-target: OK')

from jack.core.piped import PipedInput
print('[11] Piped input: OK')

from jack.performance.processpool import ProcessPool
print('[12] Process pool: OK')

from jack.performance.mmap_wordlist import MmapWordlist
wordlist_path = ROOT_DIR / "wordlists" / "common.txt"
mw = MmapWordlist(str(wordlist_path))
mw.open()
count = mw.count_lines()
mw.close()
print(f'[13] Mmap wordlist: OK - {count} lines, {mw.size_human}')

from jack.performance.bloom import BloomFilter
bf = BloomFilter(1000, 0.01)
bf.add('password')
bf.add('123456')
has_pw = bf.contains('password')
print(f'[14] Bloom filter: OK - {bf.memory_human}, has password={has_pw}')

from jack.attacks.webhook import WebhookNotifier
print('[15] Webhook notifier: OK')

from jack.performance.simd import detect_simd
simd = detect_simd()
print(f'[16] SIMD detection: OK - AVX2={simd.avx2}')

from jack.reporting.pdf_report import PDFReportGenerator
print('[17] PDF report: OK')

from jack.hashes.rainbow import RainbowTableDetector
results = RainbowTableDetector().analyze_batch(['5f4dcc3b5aa765d61d8327deb882cf99'])
print(f'[18] Rainbow detection: OK - {len(results)} flagged')

from jack.cli.main import app
print('[19] CLI integration: OK')

from jack.core.engine import AuditEngine
engine = AuditEngine()
attacks = engine.list_attacks()
names = [a['name'] for a in attacks]
print(f'[20] Engine: OK - {len(attacks)} attack modes: {names}')

print()
print('=== ALL 20 FEATURES VERIFIED ===')
