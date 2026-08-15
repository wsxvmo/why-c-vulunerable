// ledger-manager 插件 · Host 半（v9 终版, 对应 cordis_define 的 code.host）
// ============================================================================
// 用法: cordis_define 时把本文件内容作为 code.host 传入; 恢复步骤见 README.md
// 依赖: ctx.get('fs')（Host fs 服务）; harness.handle（动态插件包私有 RPC）
// 功能: ledger.scan（扫描 baseDir 下所有含 cases.json 的 run 目录）/
//       ledger.read（读单个 run 的 cases.json + logs.json + run_meta.json）
// ============================================================================
return {
  apply(ctx) {
    const fs = ctx.get('fs')
    if (fs === undefined) return
    const DEFAULT_BASE = '/home/xvmo/why-c-vulunerable/workspace/runs'
    async function readJson(dir, file) {
      try {
        const t = await fs.resolve(dir + '/' + file)
        const info = await fs.stat(t)
        if (!info) return null
        const text = await fs.readText(t)
        try { return JSON.parse(text) } catch (e) { return null }
      } catch (e) { return null }
    }
    // 扫描 baseDir 下所有含 cases.json 的 run 目录, 返回紧凑摘要
    harness.handle('ledger.scan', async (args) => {
      const baseDir = args && typeof args.baseDir === 'string' ? args.baseDir : DEFAULT_BASE
      try {
        const base = await fs.resolve(baseDir)
        const entries = await fs.listDir(base)
        const runs = []
        for (const e of entries) {
          if (e.type !== 'directory') continue
          const dir = baseDir + '/' + e.name
          const cases = await readJson(dir, 'cases.json')
          if (!cases) continue
          const meta = await readJson(dir, 'run_meta.json')
          const logs = await readJson(dir, 'logs.json')
          const counts = {}
          for (const c of cases) {
            const s = c.status || 'unknown'
            counts[s] = (counts[s] || 0) + 1
          }
          runs.push({
            runDir: dir,
            name: e.name,
            title: (meta && meta.title) || '',
            target: (meta && meta.target) || '',
            caseCount: cases.length,
            logCount: (logs || []).length,
            counts,
          })
        }
        return { baseDir, runs }
      } catch (err) {
        return { baseDir, runs: [], error: String((err && err.message) || err) }
      }
    })
    // 读单个 run 的完整台账
    harness.handle('ledger.read', async (args) => {
      const runDir = args && typeof args.runDir === 'string' ? args.runDir : ''
      if (!runDir) return { error: 'runDir required' }
      const cases = await readJson(runDir, 'cases.json')
      const logs = await readJson(runDir, 'logs.json')
      const meta = await readJson(runDir, 'run_meta.json')
      return { runDir, meta: meta || {}, cases: cases || [], logs: logs || [] }
    })
  },
}
