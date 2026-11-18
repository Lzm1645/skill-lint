import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class LintTest(unittest.TestCase):
    def run_lint(self, path):
        return subprocess.run([sys.executable, str(ROOT / "skill_lint.py"), str(path), "--json"],
                              capture_output=True, text=True)

    def test_bad_remote_blocks(self):
        result = self.run_lint(ROOT / "tests/fixtures/bad-remote")
        self.assertEqual(result.returncode, 1)
        self.assertIn('"rule": "L02"', result.stdout)
        self.assertIn('"rule": "L04"', result.stdout)

    def test_good_passes(self):
        result = self.run_lint(ROOT / "tests/fixtures/good")
        self.assertIn('"blocks": 0', result.stdout)


if __name__ == "__main__":
    unittest.main()
