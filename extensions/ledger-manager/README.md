# ledger-manager — 台账管理插件（持久化定义）

DSH **动态 Cordis 插件**的持久化存档。进程重启后插件会消失，用本目录的文件**两步恢复**。

## 组成

| 文件 | 内容 | cordis_define 参数 |
|---|---|---|
| `host.js` | Host 半（fs 直读台账 + `harness.handle` 两个 RPC） | `code.host` |
| `client.js` | Client 半（输入框"台账"按钮 + 锚定弹出面板 + Run 卡片常驻） | `code.client` |
| `README.md` | 本文件（恢复步骤） | — |

## 恢复步骤（进程重启后，任意会话）

```text
1. read /home/xvmo/why-c-vulunerable/extensions/ledger-manager/host.js      # 内容作为 code.host
   read /home/xvmo/why-c-vulunerable/extensions/ledger-manager/client.js    # 内容作为 code.client

2. cordis_define:
   plugin:  {kind: "new", idPrefix: "ledg"}
   name:    "ledger-manager"
   purpose: "审计台账管理面板：输入框工具行按钮 + 锚定弹出面板（扫描/筛选/CSV/时间线, 10s 刷新, sticky 头部）+ Run 卡片常驻底座; Host fs 直读 casefile"
   code.host:   <host.js 全文>
   code.client: <client.js 全文>

3. cordis_run（run 模式, 新 pluginId）
   → Client 包需要一次 GUI 审批（单勾即可）

4. 强刷页面（Ctrl+Shift+R）→ 输入框工具行出现"台账"按钮
```

> 插件是**进程级 + 浏览器应用级**的：同进程内所有会话共用（Host RPC + 浏览器 slot 都共享），
> 只有**进程重启**才需要重做以上步骤。

## 布局与行为（v9 终版）

- **触发器**：`conversation.input.left`（输入框工具行、"full access" 旁）"台账"胶囊按钮
- **面板**：absolute 锚定在按钮上方（`bottom: calc(100%+8px)`），680px，sticky 头部 + "收起 ✕"常驻右上角
- **常驻底座**：`tool.view.cordis`（key self）Run 卡片内同款面板，官方保证渲染兜底
- **数据**：Host `ledger.scan` 扫描 `workspace/runs/` 下含 `cases.json` 的目录；`ledger.read` 读 cases/logs/meta；10s 自动刷新
- **只读**：不改台账，状态修改仍走 `casefile.py`/agent（保留权威校验）

## 踩坑记录（开发时血泪，详见 skills/workflow-audit/SKILL.md §ledger-manager 插件踩坑记录）

- `shell.overlay` / `conversation.input.dock` 在本构建不渲染 occupant → 别用
- 侧栏 `sidebar.footer.action` 有 rail 兼容问题 → 别用
- **可行方案**：触发器 `conversation.input.left` + absolute 锚定面板；`tool.view.cordis` 兜底
- Client 无 `document`/`window` → CSV 用 textarea 全选复制

## 后续（可选）

- **静态化**（进程重启也常驻）：需改为 Typert Remote 服务 RPC（`ctx.remote.<svc>` 替代 `host.call`）、
  按 `__ModuleLoader__` 格式手写 client bundle、注册 `cordis.patch.yml` + symlink 进
  `$DSH_HOME/profiles/node_modules`、重建 web bundle、重启验证（风险：Remote 契约错则 web 起不来）。
  调研结论见会话记录; 动态插件已满足"同进程跨会话", 静态化仅买"重启存活"。
