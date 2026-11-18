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

    def test_docs_only_does_not_block(self):
        # 命名空间 URL / “never commit .env” / 散文里的 deploy 都是文档，不是能力。
        result = self.run_lint(ROOT / "tests/fixtures/noisy-prose")
        self.assertEqual(result.returncode, 0)
        self.assertIn('"blocks": 0', result.stdout)

    def test_http_link_context(self):
        # 文档里的 http 引用只 warn；代码块里的 http 才是出网路径 -> block。
        result = self.run_lint(ROOT / "tests/fixtures/http-context")
        self.assertEqual(result.returncode, 1)
        self.assertIn("文档引用里的非 HTTPS 链接", result.stdout)
        self.assertIn("非 HTTPS/IP 直连", result.stdout)

    def test_settings_write_blocks(self):
        result = self.run_lint(ROOT / "tests/fixtures/settings-writer")
        self.assertEqual(result.returncode, 1)
        self.assertIn('"rule": "L10"', result.stdout)

    def test_destructive_command_blocks(self):
        result = self.run_lint(ROOT / "tests/fixtures/destructive")
        self.assertEqual(result.returncode, 1)
        self.assertIn('"rule": "L07"', result.stdout)


if __name__ == "__main__":
    unittest.main()
