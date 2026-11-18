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
| L03 | 出网目的地：http、IP 直连、pastebin/ngrok、未声明 host | **block** / warn |
| L04 | 敏感路径与环境变量（`.ssh`、`.env`、`printenv`、Keychain） | **block** |
| L05 | 外发载荷可能含本地/敏感数据 | warn |
| L06 | 命令/代码注入面（`shell=True`、`eval`、`exec`） | warn |
| L07 | 写/删/部署无确认或 dry-run；fail-open 分支 | **block** |
| L08 | 不可信内容进入 prompt，缺「数据非指令」边界 | warn / **block** |
| L09 | 解压/归档无大小或路径限制 | warn |
| L10 | 缺 repo/license/provenance；写 hooks/settings、自更新 | warn / **block** |

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

## 样例

```text
$ python3 skill_lint.py ~/.codex/skills/mx-zixuan
/Users/.../mx-zixuan: block (1 block, 2 warn)
  [warn ] L01 未声明 allowed-tools（能力边界不可见）
  [block] L04 读取敏感信息：.env 文件  mx_zixuan.py:33
```

## 边界

- 纯静态、启发式；不执行 skill 代码，也不访问网络；
- 规则基于公开的 skill 安全实践，不覆盖所有攻击面；
- 误报请提 issue，附路径与行号。

## License

MIT
