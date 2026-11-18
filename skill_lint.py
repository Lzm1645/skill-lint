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

# L04：只在“确实去读/取”的语境里报敏感路径。扫描公开技能库时，绝大多数命中是
# 「不要提交 .env」「deny 规则里列出 ~/.ssh」这类文档/防护语句，按纯关键词报会淹掉信号。
SENSITIVE_READ = [
    (r"~/\.ssh|/\.ssh", "SSH 目录"),
    (r"id_rsa|id_ed25519", "SSH 私钥"),
    (r"\.aws/|AWS_SECRET", "AWS 凭证"),
    (r"\.config/gh", "GitHub CLI 凭证"),
    (r"\.npmrc", "npm token"),
    (r"(?<![\w.])\.env(?![\w])", ".env 文件"),
    (r"\bkeychain\b", "Keychain"),
]
SENSITIVE_COMMAND = [
    (r"\bprintenv\b", "环境变量导出"),
    (r"(?:^|[$;`]\s*)env\s*\|\s*(?:grep|rg|sort|head|tail|awk|cut|uniq|wc|tr|less|more)\b", "环境变量导出"),
    (r"security find-generic-password", "Keychain"),
]
# “读取”动作：cat/open(...)/Read(...)/dotenv 等；只用于收紧 L04，不追求完备。
ACCESS_HINT = re.compile(
    r"(?i)(?:\b(?:cat|less|more|head|tail|grep|rg|awk|sed|cp|rsync|scp|tar|read|source|dotenv)\b"
    r"|open\s*\(|read_text|read_bytes|readfile|readfilesync|Read\s*\()"
)
# 文档/防护/占位语境：命中这些词的同一行不视为“实际读取”。
SAFE_HINT = re.compile(
    r"(?i)(never|not\s+commit|do\s+not|don't|avoid|deny|block|protect|redact|ignore|placeholder"
    r"|template|gitignore|regex|pattern|noqa|SECRET_HINTS|detect|\*\*\*"
    r"|\.env\.(?:example|sample|template|test|dist))"
)

# L03：XML 命名空间是可下载 schema 的标识符，不是出网目的地；占位域名与模板 URL 同理。
SCHEMA_HOSTS = {
    "schemas.openxmlformats.org", "schemas.microsoft.com", "schemas.android.com",
    "schemas.xmlsoap.org", "www.w3.org", "openoffice.org", "json-schema.org",
    "www.sitemaps.org", "xmlns.com", "schema.org", "purl.org", "ns.adobe.com",
    "www.idpf.org", "idpf.org",
}
PLACEHOLDER_HOSTS = {"example.com", "example.org", "example.net", "www.example.com"}

# L07：只把“会实际发生的破坏性命令”当作写/删/部署路径；散文里的
# deployment/update/remove 是说明文字，不构成可执行能力。
MUTATING_CMD = re.compile(
    r"""(?ix)
    (?:^|[\s`;:=\[(])
    (?:
        rm\s+(?:-[a-z]*[rf][a-z]*|/)
      | git\s+(?:push|reset\s+--hard|clean\s+-[a-z]*f)
      | (?:docker|podman)\s+(?:push|rm)\b
      | kubectl\s+(?:apply|delete)\b
      | terraform\s+(?:apply|destroy)\b
      | (?:npm|pnpm|yarn)\s+publish\b
      | gh\s+release\s+(?:create|delete)\b
      | (?:vercel|fly|flyctl|heroku|netlify)\s+(?:deploy|--prod)\b
      | aws\s+\S+\s+(?:delete|terminate|stop|modify)\b
      | drop\s+(?:table|database|schema)\b
      | truncate\s+table\b
      | (?:psql|mysql)\b[^\n]*\b(?:drop|delete|truncate)\b
    )
    """
)


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

    # L03 出网目的地：代码块里的 http/IP 是真实的出网路径 -> block；
    # 文档/参考链接里的 http 只降为 warn，避免把“引用了一份 http 文档”当成能力。
    allowed_hosts = set()
    raw_hosts = str(fm.get("allowed-hosts") or fm.get("allowed_hosts") or "")
    for host in re.split(r"[,\s]+", raw_hosts):
        if host:
            allowed_hosts.add(host.strip().lower())
    # 出处/仓库链接是元数据，不是能力会访问的目的地。
    provenance_urls = set(re.findall(r"https?://[^\s)\"'<]+", "\n".join(str(v) for v in fm.values())))
    findings = {}  # url -> (rank, severity, message)
    for path, text in texts.items():
        in_fence = False
        for line in text.splitlines():
            stripped = line.lstrip()
            if stripped.startswith(("```", "~~~")):
                in_fence = not in_fence
                continue
            for match in re.finditer(r"https?://[^\s)\"'<]+", line):
                url = match.group(0).rstrip(";,.`")
                if not url:
                    continue
                if url in provenance_urls:
                    continue
                if re.search(r"licen[cs]e|apache\.org/licenses|opensource\.org|creativecommons", url, re.I):
                    continue
                host = re.sub(r"https?://", "", url).split("/")[0].split(":")[0].lower()
                if (host in SCHEMA_HOSTS or host in PLACEHOLDER_HOSTS
                        or host.endswith((".example", ".example.com", ".example.org", ".example.net"))
                        or (host.endswith(".internal") and host != "metadata.google.internal")  # 云元数据是真实 SSRF 目标
                        or "." not in host or host in ("0.0.0.0", "[::]")):
                    continue
                # {VAR}/$VAR/正则片段不是可访问的目的地，报出来只是噪声。
                if re.search(r"[{}|\\()\[\]$]", url) or not re.search(r"[a-z0-9]", host):
                    continue
                if host in ("localhost", "127.0.0.1"):
                    severity, message = "warn", f"本地地址：{url}（确认仅本地使用）"
                elif url.startswith("http://") or re.match(r"^\d+\.\d+\.\d+\.\d+$", host):
                    if in_fence:
                        severity, message = "block", f"非 HTTPS/IP 直连：{url}"
                    else:
                        severity, message = "warn", f"文档引用里的非 HTTPS 链接：{url}"
                elif any(bad in host for bad in ("pastebin", "transfer.sh", "webhook.site", "ngrok")):
                    severity, message = "block", f"高风险外发域名：{host}"
                elif allowed_hosts and host not in allowed_hosts:
                    severity, message = "warn", f"未声明的外发域名：{host}"
                else:
                    continue
                rank = 2 if severity == "block" else 1
                if url not in findings or rank > findings[url][0]:
                    findings[url] = (rank, severity, message)
    for url in sorted(findings):
        _, severity, message = findings[url]
        add("L03", severity, message, skill_md)

    # L04 敏感路径/环境变量：只有“实际读取/执行”才报；文档、deny 规则、占位符不报。
    for path, text in texts.items():
        for i, line in enumerate(text.splitlines(), 1):
            for pattern, label in SENSITIVE_READ:
                if re.search(pattern, line) and ACCESS_HINT.search(line) and not SAFE_HINT.search(line):
                    add("L04", "block", f"读取敏感信息：{label}", path, i)
                    break
        for i, line in enumerate(text.splitlines(), 1):
            for pattern, label in SENSITIVE_COMMAND:
                if re.search(pattern, line) and not SAFE_HINT.search(line):
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

    # L07 写操作确认门：只有真实会执行的破坏性命令才算，散文里的 deployment/update 不算。
    confirm = re.search(r"confirm|--yes|--dry-run|二次确认|确认", alltext, re.I)
    if MUTATING_CMD.search(alltext) and not confirm:
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
    # 只有“动词在目标路径附近”才算写入指令；描述性提到 settings 文件不算。
    WRITE_THEN_TARGET = re.compile(
        r"(?i)(?<![a-z_])(?:add(?:s|ed|ing)?|append(?:s|ed|ing)?|install(?:s|ed|ing)?|copy|copies|copied"
        r"|write|writes|writing|edit(?:s|ed|ing)?|update[sd]?|overwrite|replace[sd]?|patch(?:es|ed|ing)?|cp)"
        r"(?![a-z_])[^\n]{0,60}(?:settings\.json|\.claude/(?:settings|hooks|config)|\.cursor/(?:settings|hooks)"
        r"|\.codex/config|(?<![a-z])hooks?/)"
    )
    for path, text in texts.items():
        for i, line in enumerate(text.splitlines(), 1):
            if WRITE_THEN_TARGET.search(line):
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
