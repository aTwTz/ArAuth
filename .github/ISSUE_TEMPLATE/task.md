---
name: 任务 / Task
about: 任何功能、修复或重构任务。没有验收标准的 issue 不会被实现。
---

## 目标
<!-- 一句话 -->

## 验收标准
<!-- 模糊描述会被原样放大成模糊实现。必须写清： -->
- [ ] 输入/输出：
- [ ] 涉及模块：
- [ ] 非目标（明确不做什么）：
- [ ] 测试命令：`make check`；涉及 store 时补 `go -C auth-server test -tags integration ./internal/store/`，涉及浏览器流程补 `./scripts/e2e.sh`

## 上下文
<!-- 相关文件 @路径、报错堆栈、最小复现、相关 ADR/DESIGN 章节 -->
