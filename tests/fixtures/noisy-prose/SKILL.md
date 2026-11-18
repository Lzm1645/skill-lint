---
name: noisy-prose
description: documentation-heavy skill used to check false positives
allowed-tools: Read, Write
repo: https://github.com/example/noisy-prose
license: MIT
---
This skill explains deployment and update workflows in prose.

- Never commit `.env` files; keep `.env.example` in the repository.
- Compare the output with the brand profile in `.claude/product-marketing-context.md`.
- WordprocessingML documents use http://schemas.openxmlformats.org/wordprocessingml/2006/main namespaces.
- Deploy notes: a deployment with three changes is safer than one with thirty.
- Avoid reading `~/.ssh` material; deny rules should list `Read(~/.ssh/**)`.
