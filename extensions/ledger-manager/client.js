// ledger-manager 插件 · Client 半（v9 终版, 对应 cordis_define 的 code.client）
// ============================================================================
// 用法: cordis_define 时把本文件内容作为 code.client 传入; 恢复步骤见 README.md
// 依赖: slots（sidebar 无; 最终方案: conversation.input.left 触发器 + tool.view.cordis 常驻卡片）
//       host.call（动态插件包私有 RPC, 对应 host.js 的 harness.handle）; styles; ctx.get('timer')
// 布局: 输入框工具行"台账"胶囊按钮 → absolute 锚定弹出面板（sticky 头部+关闭常驻右上角）
//       + Run 卡片内常驻面板（tool.view.cordis, 官方保证渲染, 兜底可见）
// 踩坑记录见 skills/workflow-audit/SKILL.md §ledger-manager 插件踩坑记录
// ============================================================================
return {
  apply(ctx) {
    const slots = ctx.get('slots')
    if (slots === undefined) return
    styles.insert(`
.ledger-trigger { position: relative; display: inline-flex; align-items: center; margin: 0 2px; }
.ledger-trigger-btn { cursor: pointer; white-space: nowrap; display: inline-flex; align-items: center; gap: 4px; color: var(--dsw-alias-label-secondary); background: var(--dsw-alias-bg-layer-1); border: 1px solid var(--dsw-alias-border-l1); border-radius: 999px; padding: 3px 10px; font-size: 12px; font-family: inherit; }
.ledger-trigger-btn:hover { background: var(--dsw-alias-bg-layer-2); color: var(--dsw-alias-label-primary); }
.ledger-trigger-btn.on { color: var(--dsw-alias-brand-primary); border-color: var(--dsw-alias-brand-primary); }
.ledger-pop { position: absolute; bottom: calc(100% + 8px); left: 0; width: min(680px, calc(100vw - 48px)); max-height: 60vh; overflow: auto; box-sizing: border-box; z-index: 30; background: var(--dsw-alias-bg-base); color: var(--dsw-alias-label-primary); border: 1px solid var(--dsw-alias-border-l1); border-radius: 12px; box-shadow: 0 8px 30px rgba(0,0,0,.35); padding: 12px; font-size: 13px; }
.ledger-pop input, .ledger-pop select, .ledger-pop button, .ledger-pop textarea, .ledger-card input, .ledger-card select, .ledger-card button, .ledger-card textarea {
  background: var(--dsw-alias-bg-layer-1); color: var(--dsw-alias-label-primary);
  border: 1px solid var(--dsw-alias-border-l1); border-radius: 6px; padding: 3px 8px;
  margin: 2px; font-size: 12px; }
.ledger-head { position: sticky; top: -12px; margin: -12px -12px 8px; padding: 12px; display: flex; align-items: center; gap: 8px; background: var(--dsw-alias-bg-base); border-bottom: 1px solid var(--dsw-alias-border-l1); border-radius: 12px 12px 0 0; z-index: 1; }
.ledger-card .ledger-head { background: var(--dsw-alias-bg-layer-1); }
.ledger-close { margin-left: auto; }
.ledger-sub { color: var(--dsw-alias-label-secondary); font-size: 11px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; min-width: 0; flex: 1; }
.ledger-row { display: flex; align-items: center; gap: 6px; flex-wrap: wrap; }
.ledger-err { color: var(--dsw-alias-state-error-primary); font-size: 12px; margin: 4px 0; }
.ledger-runs { display: flex; flex-wrap: wrap; gap: 4px; margin: 6px 0; }
.ledger-chip { cursor: pointer; }
.ledger-chip.sel { border-color: var(--dsw-alias-brand-primary); }
.ledger-pop table, .ledger-card table { width: 100%; border-collapse: collapse; margin-top: 6px; }
.ledger-pop th, .ledger-pop td, .ledger-card th, .ledger-card td { border-bottom: 1px solid var(--dsw-alias-border-l1); padding: 4px 6px; text-align: left; font-size: 12px; }
.ledger-ev { max-width: 280px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.ledger-count { font-size: 11px; margin-right: 6px; }
.ledger-st { font-size: 11px; padding: 1px 6px; border-radius: 8px; border: 1px solid var(--dsw-alias-border-l1); }
.st-confirmed { color: var(--dsw-alias-state-success-primary); }
.st-killed { color: var(--dsw-alias-state-error-primary); }
.st-hypothesis, .st-investigating { color: var(--dsw-alias-state-warn-primary); }
.ledger-csv textarea { width: 100%; box-sizing: border-box; }
.ledger-logs { margin-top: 8px; }
.ledger-logs ul { margin: 4px 0; padding-left: 16px; font-size: 11px; }
.ledger-card { box-sizing: border-box; width: 100%; max-height: 60vh; overflow: auto; background: var(--dsw-alias-bg-layer-1); color: var(--dsw-alias-label-primary); border: 1px solid var(--dsw-alias-border-l2); border-radius: 10px; padding: 12px; font-size: 13px; }
`)
    const DEFAULT_BASE = '/home/xvmo/why-c-vulunerable/workspace/runs'
    const h = React.createElement
    function StatusPill(props) {
      const st = props.status || 'unknown'
      return h('span', { className: 'ledger-st st-' + st }, st)
    }
    function PanelBody() {
      const [baseDir, setBaseDir] = React.useState(DEFAULT_BASE)
      const [runs, setRuns] = React.useState([])
      const [error, setError] = React.useState('')
      const [loading, setLoading] = React.useState(false)
      const [sel, setSel] = React.useState(null)
      const [data, setData] = React.useState(null)
      const [statusFilter, setStatusFilter] = React.useState('all')
      const [classFilter, setClassFilter] = React.useState('')
      const [csv, setCsv] = React.useState('')
      const loadRuns = async () => {
        setLoading(true)
        setError('')
        try {
          const r = await host.call('ledger.scan', { baseDir })
          setRuns(r.runs || [])
          if (r.error) setError(r.error)
        } catch (e) { setError(String((e && e.message) || e)) }
        setLoading(false)
      }
      const selectRun = async (run) => {
        setSel(run.runDir)
        try {
          const d = await host.call('ledger.read', { runDir: run.runDir })
          setData(d)
        } catch (e) { setData(null); setError(String((e && e.message) || e)) }
      }
      React.useEffect(() => { loadRuns() }, [])
      React.useEffect(() => {
        const t = ctx.get('timer')
        if (!t) return
        return t.interval(() => loadRuns(), 10000)
      }, [baseDir])
      const cases = (data && data.cases) || []
      const counts = {}
      for (const c of cases) { const s = c.status || 'unknown'; counts[s] = (counts[s] || 0) + 1 }
      const filtered = cases.filter((c) => {
        if (statusFilter !== 'all' && (c.status || 'unknown') !== statusFilter) return false
        if (classFilter && !(c.bugClass || '').toLowerCase().includes(classFilter.toLowerCase())) return false
        return true
      })
      const exportCsv = () => {
        const head = ['id', 'status', 'bugClass', 'severity', 'file', 'line', 'evidence', 'title']
        const rows = filtered.map((c) => [c.id, c.status, c.bugClass, c.severity, c.file, c.line, (c.evidence || '').replace(/\n/g, ' '), (c.title || '').replace(/\n/g, ' ')])
        setCsv([head.join(','), ...rows.map((r) => r.map((v) => '"' + String(v === undefined ? '' : v).replace(/"/g, '""') + '"').join(','))].join('\n'))
      }
      return h('div', null,
        h('div', { className: 'ledger-row' },
          h('input', { value: baseDir, onChange: (e) => setBaseDir(e.target.value), style: { flex: 1 } }),
          h('button', { onClick: () => { setRuns([]); setSel(null); setData(null); loadRuns() } }, '重新扫描'),
        ),
        error ? h('div', { className: 'ledger-err' }, error) : null,
        h('div', { className: 'ledger-runs' },
          runs.length === 0
            ? h('span', { className: 'ledger-sub' }, '无台账（未找到 cases.json）')
            : runs.map((r) => h('button', {
              key: r.runDir,
              className: 'ledger-chip' + (sel === r.runDir ? ' sel' : ''),
              onClick: () => selectRun(r),
              title: r.target || r.name,
            }, r.name + ' (' + r.caseCount + ')')),
        ),
        sel && data ? h('div', { className: 'ledger-body' },
          h('div', { className: 'ledger-row' },
            h('span', { className: 'ledger-sub' }, '共 ' + cases.length + ' 案件'),
            Object.keys(counts).map((s) => h('span', { key: s, className: 'ledger-count st-' + s }, s + ':' + counts[s])),
            h('select', { value: statusFilter, onChange: (e) => setStatusFilter(e.target.value) },
              [h('option', { value: 'all' }, '全部状态'), ...Object.keys(counts).map((s) => h('option', { value: s }, s))]),
            h('input', { placeholder: '按类过滤', value: classFilter, onChange: (e) => setClassFilter(e.target.value) }),
            h('button', { onClick: exportCsv }, '导出 CSV'),
          ),
          h('table', null,
            h('thead', null, h('tr', null, ['ID', '状态', '类', '严重度', '位置', '证据'].map((t) => h('th', { key: t }, t)))),
            h('tbody', null, filtered.map((c) => h('tr', { key: c.id },
              h('td', null, c.id),
              h('td', null, h(StatusPill, { status: c.status })),
              h('td', null, c.bugClass || ''),
              h('td', null, c.severity || ''),
              h('td', null, (c.file || '') + (c.line ? ':' + c.line : '')),
              h('td', { className: 'ledger-ev' }, (c.evidence || '').slice(0, 120)),
            ))),
          ),
          csv ? h('div', { className: 'ledger-csv' },
            h('div', { className: 'ledger-row' },
              h('span', { className: 'ledger-sub' }, 'CSV（全选复制）'),
              h('button', { onClick: () => setCsv('') }, '收起'),
            ),
            h('textarea', { readOnly: true, value: csv, rows: 6 }),
          ) : null,
          (data && data.logs && data.logs.length) ? h('div', { className: 'ledger-logs' },
            h('div', { className: 'ledger-sub' }, '证据时间线（' + data.logs.length + '）'),
            h('ul', null, data.logs.slice(-15).reverse().map((l, i) => h('li', { key: i },
              (l.at || '') + ' [' + (l.case || '') + '] ' + (l.stage || '') + ' ' + (l.verdict || '') + ' — ' + (l.evidence || '').slice(0, 100)))),
          ) : null,
        ) : null,
      )
    }
    function ComposerTrigger() {
      const [open, setOpen] = React.useState(false)
      return h('div', { className: 'ledger-trigger' },
        h('button', {
          type: 'button',
          className: 'ledger-trigger-btn' + (open ? ' on' : ''),
          title: '台账管理',
          'aria-label': '台账管理',
          'aria-expanded': open,
          onClick: () => setOpen((v) => !v),
        }, '台账'),
        open ? h('div', { className: 'ledger-pop' },
          h('div', { className: 'ledger-head' },
            h('strong', null, '台账管理'),
            h('span', { className: 'ledger-sub' }, '台账'),
            h('button', { className: 'ledger-close', onClick: () => setOpen(false) }, '收起 ✕'),
          ),
          h(PanelBody, null),
        ) : null,
      )
    }
    function CardPanel() {
      return h('div', { className: 'ledger-card' },
        h('div', { className: 'ledger-head' },
          h('strong', null, '台账管理（ledger-manager）'),
          h('span', { className: 'ledger-sub' }, '常驻面板'),
          h('button', { className: 'ledger-close', onClick: () => {} }, ''),
        ),
        h(PanelBody, null),
      )
    }
    slots.inject('conversation.input.left', () => slots.register(
      { name: 'conversation.input.left', id: 'ledger-trigger', order: 100 },
      () => h(ComposerTrigger, null),
    ))
    slots.inject('tool.view.cordis', () => slots.register(
      { name: 'tool.view.cordis', key: 'self' },
      () => h(CardPanel, null),
    ))
  },
}
