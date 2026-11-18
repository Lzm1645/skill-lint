#!/usr/bin/env python3
"""skill-lint: 静态检查 AI Agent Skill 的权限、注入与数据外发风险。

用法：
    python3 skill_lint.py <skill 目录或 SKILL.md> [--json] [--quiet]

规则 L01–L10 见 README。任何 block 级问题都会以非 0 退出码结束（适合 CI）。
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

TEXT_EXT = {".md", ".txt", ".py", ".js", ".ts", ".sh", ".bash", ".zsh", ".json", ".yaml", ".yml"}
SENSITIVE = [
    (r"~/\.ssh|/\.ssh", "SSH 目录"),
    (r"id_rsa|id_ed25519", "SSH 私钥"),
    (r"\.aws/|AWS_SECRET", "AWS 凭证"),
    (r"\.config/gh", "GitHub CLI 凭证"),
    (r"\.npmrc", "npm token"),
    (r"(?<![\w.])\.env(?![\w])", ".env 文件"),
    (r"printenv|\benv\s*\|", "环境变量导出"),
    (r"security find-generic-password|keychain", "Keychain"),
]
MUTATING = r"delete|remove|destroy|deploy|--prod|\bapply\b|\bwrite\b|\bupdate\b|\bmanage\b"
HOOK_TARGET = r"settings\.json|\.claude/|\.cursor/|hooks?"


def read_frontmatter(text: str) -> dict:
    if not text.startswith("---"):
        return {}
    end = text.find("\n---", 3)
    if end < 0:
        return {}
    block = text[3:end]
    meta = {}
    for line in block.splitlines():
        if ":" in line and not line.strip().startswith("#"):
            key, value = line.split(":", 1)
            meta[key.strip()] = value.strip().strip("'\"")
    return meta


def collect_files(root: Path) -> list[Path]:
    if root.is_file():
        return [root]
    return [p for p in root.rglob("*") if p.is_file() and p.suffix.lower() in TEXT_EXT and ".git" not in p.parts]


def lint(root: Path) -> dict:
    files = collect_files(root)
    texts = {p: p.read_text(errors="ignore") for p in files}
    skill_md = next((p for p in files if p.name.lower() == "skill.md"), None)
    fm = read_frontmatter(texts[skill_md]) if skill_md else {}
    alltext = "\n".join(texts.values())
    issues = []

    def add(rule, severity, message, path=None, line=None):
        issues.append({"rule": rule, "severity": severity, "message": message,
                       "path": str(path) if path else "", "line": line})

    # L01 权限声明
    tools = str(fm.get("allowed-tools") or fm.get("allowed_tools") or "")
    if not tools:
        add("L01", "warn", "未声明 allowed-tools（能力边界不可见）", skill_md)
    elif re.search(r"Bash\s*\(\s*\*\s*\)|Bash\s*\(\s*\)|Write\s*\(\s*\*\s*\)", tools):
        add("L01", "block", f"allowed-tools 过宽：{tools}", skill_md)

    # L02 远程脚本直执行
    for path, text in texts.items():
        for i, line in enumerate(text.splitlines(), 1):
            if re.search(r"(curl|wget)[^\n]*\|\s*(bash|sh|zsh)", line):
                add("L02", "block", "远程脚本管道执行", path, i)
            if re.search(r"npx\s+-y\s", line) and "@" not in line:
                add("L02", "warn", "npx -y 未固定版本", path, i)
            if re.search(r"pip\s+install\s+(?!-r)[^\n]*", line) and "==" not in line:
                add("L02", "warn", "pip install 未固定版本", path, i)

    # L03 出网目的地
    allowed_hosts = set()
    raw_hosts = str(fm.get("allowed-hosts") or fm.get("allowed_hosts") or "")
    for host in re.split(r"[,\s]+", raw_hosts):
        if host:
            allowed_hosts.add(host.strip().lower())
    urls = set(re.findall(r"https?://[^\s)\"'<]+", alltext))
    for url in sorted(urls):
        if re.search(r"licen[cs]e|apache\.org/licenses|opensource\.org|creativecommons", url, re.I):
            continue
        host = re.sub(r"https?://", "", url).split("/")[0].split(":")[0].lower()
        if host in ("localhost", "127.0.0.1"):
            add("L03", "warn", f"本地地址：{url}（确认仅本地使用）", skill_md)
            continue
        if url.startswith("http://") or re.match(r"^\d+\.\d+\.\d+\.\d+$", host):
            add("L03", "block", f"非 HTTPS/IP 直连：{url}", skill_md)
        elif any(bad in host for bad in ("pastebin", "transfer.sh", "webhook.site", "ngrok")):
            add("L03", "block", f"高风险外发域名：{host}", skill_md)
        elif allowed_hosts and host not in allowed_hosts:
            add("L03", "warn", f"未声明的外发域名：{host}", skill_md)

    # L04 敏感路径/环境变量
    for path, text in texts.items():
        for i, line in enumerate(text.splitlines(), 1):
            for pattern, label in SENSITIVE:
                if re.search(pattern, line):
                    add("L04", "block", f"读取敏感信息：{label}", path, i)
                    break

    # L05 外发载荷
    for path, text in texts.items():
        for i, line in enumerate(text.splitlines(), 1):
            if re.search(r"requests\.(post|put)|fetch\(|curl[^\n]*(-d|--data|-F|-T)", line):
                if re.search(r"open\(|os\.environ|glob\(|transcript|history", line):
                    add("L05", "warn", "外发内容可能包含本地/敏感数据", path, i)

    # L06 注入面
    for path, text in texts.items():
        for i, line in enumerate(text.splitlines(), 1):
            if re.search(r"shell\s*=\s*True|os\.system|os\.popen|eval\(|exec\(", line):
                add("L06", "warn", "命令/代码注入面（shell=True/eval/exec）", path, i)

    # L07 写操作确认门
    confirm = re.search(r"confirm|--yes|--dry-run|二次确认|确认", alltext, re.I)
    if re.search(MUTATING, alltext, re.I) and not confirm:
        add("L07", "block", "存在写/删/部署路径但没有确认或 dry-run", skill_md)
    if re.search(r"else\s*:\s*\n\s+[^\n]*(delete|remove|manage)\(", alltext):
        add("L07", "block", "fail-open：识别失败时落入写操作分支", skill_md)

    # L08 不可信内容边界
    if re.search(r"WebFetch|browser|requests\.get", alltext) and not re.search(r"data not instructions|不可信|untrusted", alltext, re.I):
        add("L08", "warn", "读取外部内容后未见「数据非指令」边界", skill_md)
    if re.search(r"follow instructions from (the )?(page|log|output)", alltext, re.I):
        add("L08", "block", "正文要求遵循外部内容中的指令", skill_md)

    # L09 归档处理
    for path, text in texts.items():
        for i, line in enumerate(text.splitlines(), 1):
            if re.search(r"extractall|unzip|tar\s+-x", line) and not re.search(r"limit|max|safe|temp", line, re.I):
                add("L09", "warn", "解压无大小/路径限制", path, i)

    # L10 可追溯/自更新
    if not (fm.get("repo") or fm.get("license") or fm.get("provenance")):
        add("L10", "warn", "缺少 repo/license/provenance", skill_md)
    for path, text in texts.items():
        for i, line in enumerate(text.splitlines(), 1):
            if re.search(HOOK_TARGET, line) and re.search(r"write|update|install|upgrade", line):
                add("L10", "block", "写 hooks/settings 或自更新", path, i)

    blocks = [i for i in issues if i["severity"] == "block"]
    warns = [i for i in issues if i["severity"] == "warn"]
    return {"path": str(root), "frontmatter": fm,
            "result": "block" if blocks else ("warn" if warns else "pass"),
            "blocks": len(blocks), "warns": len(warns), "issues": issues}


def main() -> int:
    parser = argparse.ArgumentParser(description="Static lint for AI agent skills")
    parser.add_argument("target", type=Path)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()
    if not args.target.exists():
        print(f"not found: {args.target}", file=sys.stderr)
        return 2
    report = lint(args.target)
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=1))
    elif not args.quiet:
        print(f"{report['path']}: {report['result']} ({report['blocks']} block, {report['warns']} warn)")
        for issue in report["issues"]:
            loc = f"{issue['path']}:{issue['line']}" if issue["line"] else issue["path"]
            print(f"  [{issue['severity']:<5}] {issue['rule']} {issue['message']}  {loc}")
    return 1 if report["blocks"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
