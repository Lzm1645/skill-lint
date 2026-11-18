# skill-lint

静态检查 AI Agent Skill 的权限、注入与数据外发风险。像 `npm audit`，但对象是 `SKILL.md` + 附带脚本。

## 为什么

Agent Skill 通常包含「给 agent 的指令 + 可执行脚本 + 外部服务」。风险不在模型，而在这三样东西的边界：

- 权限声明缺失，能力远大于声明；
- 远程脚本直接执行（`curl | bash`）；
- 读 `~/.ssh`、`.env`、Keychain；
- 把本地数据/转录发到第三方；
- 写操作没有确认门，失败时 fail-open；
- 外部内容（网页/日志）被当成指令。

## 规则（L01–L10）

| 规则 | 检查 | 级别 |
|---|---|---|
| L01 | 权限声明：缺 `allowed-tools` / 过宽 `Bash(*)` | warn / **block** |
| L02 | 远程脚本直执行、未固定版本的 pip/npx | **block** / warn |
| L03 | 出网目的地：http、IP 直连、pastebin/ngrok、未声明 host（跳过 XML 命名空间/占位域名/模板 URL） | **block** / warn |
| L04 | 实际读取敏感路径/环境（`.ssh`、`.env`、`printenv`、Keychain）；文档里提到、deny 规则、占位符不算 | **block** |
| L05 | 外发载荷可能含本地/敏感数据 | warn |
| L06 | 命令/代码注入面（`shell=True`、`eval`、`exec`） | warn |
| L07 | 破坏性命令（`rm -rf`、`terraform apply`、`git push` 等）无确认或 dry-run；fail-open 分支 | **block** |
| L08 | 不可信内容进入 prompt，缺「数据非指令」边界 | warn / **block** |
| L09 | 解压/归档无大小或路径限制 | warn |
| L10 | 缺 repo/license/provenance；写 settings/hooks、自更新 | warn / **block** |

## 用法

```bash
python3 skill_lint.py path/to/skill
python3 skill_lint.py path/to/skill --json
```

退出码：0 = 通过/仅警告，1 = 有 block，2 = 路径不存在。

## CI 示例

```yaml
- name: skill lint
  run: python3 skill_lint.py skills/my-skill
```

## 公开仓库扫描（2026-11）

用本工具扫描了 29 个公开 Agent Skill 仓库（1,352 个 skill，覆盖 dsh / Claude Code / Codex 生态），
记录 block/warn 分布、高频风险模式、逐条误报审计和规则收敛前后对比：

- 报告：[scan/report-2026-11.md](scan/report-2026-11.md)
- 可复现脚本：[scan/scan_public.py](scan/scan_public.py)（`scan/repos.json` 固定到仓库 commit）
- 汇总数据：[scan/results-2026-11-19.json](scan/results-2026-11-19.json)

```bash
python3 scan/scan_public.py --config scan/repos.json --json /tmp/skills.json
```

## 样例

```text
$ python3 skill_lint.py ~/.codex/skills/mx-zixuan
/Users/.../mx-zixuan: block (1 block, 2 warn)
  [warn ] L01 未声明 allowed-tools（能力边界不可见）
  [block] L04 读取敏感信息：SSH 私钥  scripts/collect.py:41
```

## 边界

- 纯静态、启发式；不执行 skill 代码，也不访问网络；
- 规则基于公开的 skill 安全实践，不覆盖所有攻击面；
- 误报请提 issue，附路径与行号。

## License

MIT
