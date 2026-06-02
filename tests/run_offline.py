"""Run all offline tests (no lab needed).

    python tests/run_offline.py
"""
import sys, os, glob, subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
env = dict(os.environ, PYTHONPATH=REPO, PYTHONIOENCODING="utf-8")

rc = 0
for f in sorted(glob.glob(os.path.join(HERE, "test_*.py"))):
    print(f"\n========== {os.path.basename(f)} ==========")
    rc |= subprocess.run([sys.executable, f], env=env).returncode

print("\n==============================")
print("ALL OFFLINE TESTS PASSED" if rc == 0 else "SOME OFFLINE TESTS FAILED")
sys.exit(rc)
