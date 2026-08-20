#!/usr/bin/env python3
"""dedup_candidates.py — 候选点去重聚合工具 (确定性, 无模型)

输入: recon-candidates.json (按类分组的候选点) + call→method 映射
输出: 去重聚合后的候选点 (副本去重 + 函数级聚合)

聚合规则:
1. 副本去重: 同内容文件 (MD5 相同) 的候选只保留规范路径, 其余标 dup_of。
2. 函数级聚合: 同一 (file, function, class) 的候选合并为一条,
   保留最高 tier + 全部行号明细 (agg_lines), evidence 取 tier 最高者。
   - shell/python 类 (joern 无方法概念) 按 (file, line, class) 保留, 不聚合。
3. 聚合不跨类: 同函数不同 class 的候选各自保留 (防掩盖多根因)。

用法:
  python3 dedup_candidates.py <recon-candidates.json> <call-method-map.json> [--canon <file>...]
"""
import json, sys, hashlib, os, re

def load(path):
    with open(path) as f: return json.load(f)

def flatten(d):
    out = []
    for cls, items in d.items():
        if isinstance(items, list):
            for it in items:
                out.append({**it, 'class': it.get('class', cls)})
    return out

def file_md5(rel, target_root):
    p = os.path.join(target_root, rel)
    try:
        with open(p, 'rb') as f: return hashlib.md5(f.read()).hexdigest()
    except FileNotFoundError:
        return None

def extract_func(c, call_map):
    """候选点 -> 函数名: 优先 call_map (CPG 实地映射), 否则 evidence 首 token"""
    key = f"{c.get('file','')}:{int(c.get('line',0))}"
    if key in call_map:
        return call_map[key]
    m = re.match(r'^([A-Za-z_][A-Za-z0-9_]*)\b', c.get('evidence',''))
    return m.group(1) if m else '?'

TIER_RANK = {'ALERT': 3, 'HIGH': 2, 'HIT': 1, 'LOW': 0}

def main():
    if len(sys.argv) < 3:
        print(__doc__); sys.exit(1)
    cand_file, map_file = sys.argv[1], sys.argv[2]
    target_root = os.environ.get('TARGET_ROOT', '/home/xvmo/exploit-src/test-libsecurity1-workflow')
    canon_files = sys.argv[3:] or []

    cands = flatten(load(cand_file))
    call_map = load(map_file)
    total = len(cands)
    # ---- 1. 副本去重 (MD5) ----
    # 自动发现副本对: 同目录下同内容文件 (security_set.sh vs init-bottom/security_set)
    # 规范路径: 用户指定 (--canon) 或先出现的
    hashes = {}
    for c in cands:
        rel = c.get('file','')
        h = file_md5(rel, target_root)
        if h: hashes.setdefault(h, []).append(rel)
    dup_map = {}  # dup -> canon
    for h, files in hashes.items():
        if len(files) < 2: continue
        uniq = sorted(set(files))
        # canon: 用户指定优先, 否则路径含 init-bottom/ 或最先出现
        canon = next((f for f in canon_files if f in uniq), uniq[0])
        for f in uniq:
            if f != canon: dup_map[f] = canon

    after_dedup = []
    for c in cands:
        f = c.get('file','')
        if f in dup_map:
            c['dup_of'] = dup_map[f]
        after_dedup.append(c)
    dup_count = sum(1 for c in after_dedup if c.get('dup_of'))

    # ---- 2. 函数级聚合 ----
    AGG_EXEMPT = {'shell-injection', 'eval-injection', 'unsafe-deserialization', 'entry-points'}
    groups = {}
    for c in after_dedup:
        if c.get('dup_of'):
            continue  # 物理去重: dup 不参与聚合
        f, cls = c.get('file',''), c.get('class','')
        if cls in AGG_EXEMPT:
            key = (f, c.get('line'), cls)   # 按行保留 (shell/python 无函数概念)
        else:
            fn = extract_func(c, call_map)
            if fn == '?':
                # 无法归属函数的候选(头文件/grep 兜底/宏) → 按行保留, 防跨函数误并
                key = (f, c.get('line'), cls)
            else:
                key = (f, fn, cls)          # 按函数聚合
        groups.setdefault(key, []).append(c)

    out = []
    for (f, fn, cls), items in groups.items():
        lines = sorted({int(x.get('line',0)) for x in items})
        best = max(items, key=lambda x: TIER_RANK.get(x.get('tier',''), 0))
        rec = {
            'file': f,
            'line': min(lines) if lines else best.get('line', 0),
            'class': cls,
            'cwe': best.get('cwe', []),
            'query': best.get('query', ''),
            'tier': best.get('tier', 'HIT'),
            'evidence': best.get('evidence', ''),
            'agg_lines': lines,
            'agg_count': len(items),
        }
        if fn != '?': rec['function'] = fn
        out.append(rec)

    out.sort(key=lambda x: (x['file'], x['line'], x['class']))

    # ---- 报告 ----
    print(f"输入候选: {total}")
    print(f"副本 dup 标记: {dup_count} 条 (去重后保留: {total - dup_count})")
    print(f"函数级聚合后: {len(out)} 条 (总降幅 {(total-len(out))/total*100:.0f}%)")
    from collections import Counter
    print("\n按类 (前 -> 后):")
    before = Counter(x['class'] for x in cands)
    after = Counter(x['class'] for x in out)
    for cls in sorted(before):
        print(f"  {cls:24s} {before[cls]:4d} -> {after.get(cls,0):4d}")

    # 输出
    base = os.path.splitext(cand_file)[0]
    out_path = base + '.dedup.json'
    with open(out_path, 'w') as f:
        json.dump(out, f, ensure_ascii=False, indent=1)
    print(f"\n输出: {out_path}")

if __name__ == '__main__':
    main()
