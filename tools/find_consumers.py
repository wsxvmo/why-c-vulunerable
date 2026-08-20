#!/usr/bin/env python3
"""find_consumers.py — 消费者树发现 (确定性, 无模型, 通用版)

输入: 目标库名/头文件名/导出符号, 扫描同发行版源码目录
输出: consumers[] — 链接该库/引用该头文件/调用导出符号的源码树

扫描方式 (三层证据, 任一命中即消费者候选):
  1. 链接声明: configure.ac/Makefile 的 AC_CHECK_LIB / -l<lib> / pkg-config <lib> / Cargo.toml / go.mod
  2. 头文件引用: #include <libXXX.h> (C) / use xxx:: (Rust) / import (Go/Python)
  3. 符号调用: 导出符号的 调用/取址/赋值/方法表 多形态

排除: 含目标库实现文件 (与目标树同名 .c/.rs/.go) 的包 = 目标复制品, 非消费者。

用法:
  python3 find_consumers.py --target <目标树> --scan-root <同发行版源码根>
    [--lib security_conf] [--headers libsecurity_conf.h] [--symbols security_config_module_set]
    [--lang c|rust|go|python] [--pkg-pattern "*.src"]
"""
import argparse, os, re, subprocess, json, glob as _glob

# ---- 语言相关模式 ----
LANG_CONF = {
    "c": {
        "src_globs": ("*.{c,cpp,cc,h,hpp}",),
        "link_files": ("*.{ac,am,m4,in,spec,pro,cmake}", "CMakeLists.txt"),
        "header_pat": lambda h: rf'#include\s*[<"][^>"]*{re.escape(os.path.basename(h))}[>"]',
        "header_globs": ("*.{c,cpp,h,hpp,cc}",),
        "impl_exts": (".c", ".cpp", ".cc"),
    },
    "cpp": {
        "src_globs": ("*.{cpp,cc,cxx,c,h,hpp}",),
        "link_files": ("CMakeLists.txt", "*.{cmake,pro,ac,am,spec}"),
        "header_pat": lambda h: rf'#include\s*[<"][^>"]*{re.escape(os.path.basename(h))}[>"]|\b{re.escape(os.path.basename(h).replace(".h",""))}::',
        "header_globs": ("*.{cpp,cc,cxx,c,h,hpp}",),
        "impl_exts": (".cpp", ".cc", ".cxx"),
    },
    "rust": {
        "src_globs": ("*.rs",),
        "link_files": ("Cargo.toml", "*.toml"),
        "header_pat": lambda h: rf'\buse\s+[\w:]*{re.escape(h.replace(".rs","").replace(".h",""))}\b|{re.escape(h)}::',
        "header_globs": ("*.rs",),
        "impl_exts": (".rs",),
    },
    "go": {
        "src_globs": ("*.go",),
        "link_files": ("go.mod",),
        "header_pat": lambda h: rf'"{re.escape(h)}"|{re.escape(h)}\.',
        "header_globs": ("*.go",),
        "impl_exts": (".go",),
    },
    "python": {
        "src_globs": ("*.py",),
        "link_files": ("setup.py", "pyproject.toml", "requirements*.txt"),
        "header_pat": lambda h: rf'(from|import)\s+{re.escape(h.replace(".py",""))}',
        "header_globs": ("*.py",),
        "impl_exts": (".py",),
    },
}

# 通用文件名(不参与复制品判别 — main.cpp/test_*.c/poc_*.py 等各项目都有)
GENERIC_IMPL = {"main.cpp", "main.c", "main.py", "test_main.cpp"}

def rg(pattern, root, globs):
    cmd = ["rg", "-l", "--no-ignore", pattern, root]
    for g in globs: cmd += ["-g", g]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        return r.stdout.strip().split("\n") if r.stdout.strip() else []
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return []

def find_src_root(pkg_dir):
    """在包目录下定位实际源码根 (extracted/src 或含构建文件的嵌套目录)"""
    for cand in [os.path.join(pkg_dir, "extracted", "src"), pkg_dir]:
        if os.path.isdir(cand): return cand
    for root, dirs, files in os.walk(pkg_dir):
        if any(f in files for f in ("configure.ac", "Makefile.am", "CMakeLists.txt", "Cargo.toml", "go.mod", "setup.py")):
            return root
        dirs[:] = [d for d in dirs if d not in (".git", "node_modules", "poc", ".pi", "target", "vendor")]
    return pkg_dir

def collect_impl_basenames(target):
    """从目标树收集实现文件名 basename 集合 (排除复制品用, 跳过通用名)"""
    names = set()
    for ext in (".c", ".cpp", ".cc", ".rs", ".go", ".py"):
        for f in _glob.glob(os.path.join(target, "**", f"*{ext}"), recursive=True):
            b = os.path.basename(f)
            # 通用名 (main/test/poc 等各项目都有) 不参与复制品判别
            if b in GENERIC_IMPL or b.startswith(("test_", "poc_", "disconf_")):
                continue
            names.add(b)
    return names

def auto_extract(target, lang):
    """--auto: 从目标树自动提取 库名/头文件名/导出符号 (确定性)"""
    lib = ""
    headers = []
    symbols = []

    # ---- 库名: lib_LTLIBRARIES / add_library / *.la / AC_INIT ----
    # 优先 lib_LTLIBRARIES (最精确: 列出真实库文件); 多库时取最长名 (最具体)
    la = _glob.glob(os.path.join(target, "**", "*.la"), recursive=True)
    for f in la:
        m = re.search(r'([\w-]+)\.la$', os.path.basename(f))
        if m:
            lib = m.group(1).replace("lib", "", 1) if m.group(1).startswith("lib") else m.group(1)
            break
    if not lib:
        for f in _glob.glob(os.path.join(target, "**", "Makefile.am"), recursive=True):
            try:
                content = open(f, errors="ignore").read()
            except OSError:
                continue
            ms = re.findall(r'lib_LTLIBRARIES\s*=\s*([^\n]+)', content)
            if ms:
                names = re.findall(r'([\w.\-]+)\.la', " ".join(ms))
                if names:
                    # 取最长名 = 最具体 (security_conf > security)
                    lib = max(names, key=len).replace("lib", "", 1)
                    break
    if not lib:
        for f in _glob.glob(os.path.join(target, "**", "configure.ac"), recursive=True):
            m = re.search(r'AC_INIT\(\s*\[?([\w\-]+)\]?', open(f, errors="ignore").read())
            if m:
                lib = m.group(1).replace("lib", "", 1)
                break
    if not lib:
        # CMake: add_library(<name> SHARED/STATIC ...)
        for f in _glob.glob(os.path.join(target, "**", "CMakeLists.txt"), recursive=True):
            m = re.search(r'add_library\(\s*([\w\-]+)\s+(SHARED|STATIC|OBJECT|MODULE)', open(f, errors="ignore").read())
            if m:
                lib = m.group(1).replace("lib", "", 1)
                break

    # ---- 头文件名: 递归 include/ 下的 .h (保留相对 include 的路径, 过滤通用名) ----
    # 用 "相对路径" 而非 basename: kylin-ai/ai-base/vision.h 有专属前缀, 精确匹配消费者;
    # config.h/common.h/base.h 等通用名在任意项目都存在 → 排除, 防假命中。
    GENERIC_HDR = {"config.h", "common.h", "base.h", "version.h", "debug.h", "types.h",
                   "utils.h", "util.h", "log.h", "logger.h", "error.h", "main.h", "global.h"}
    inc_headers = []
    for inc_dir in _glob.glob(os.path.join(target, "**", "include"), recursive=True):
        for f in _glob.glob(os.path.join(inc_dir, "**", "*.h"), recursive=True) + \
                 _glob.glob(os.path.join(inc_dir, "**", "*.hpp"), recursive=True):
            rel = os.path.relpath(f, inc_dir)   # 如 kylin-ai/ai-base/vision.h
            if os.path.basename(rel) in GENERIC_HDR:
                continue
            inc_headers.append((f, rel))
    if not inc_headers:
        inc_headers = [(f, os.path.basename(f)) for f in _glob.glob(os.path.join(target, "**", "*.h"), recursive=True)[:12]]
    headers = [rel for _, rel in inc_headers]

    # ---- 导出符号: 头文件里的函数声明 ----
    # C:   ^type name(params);  (排除 static/inline/类型名)
    # C++: ClassName::method( 或 自由函数 type name(params)  (public 导出面)
    if lang in ("c", "cpp"):
        seen = set()
        TYPE_WORDS = {"uint32_t","uint64_t","int32_t","int64_t","uint8_t","int8_t","uint16_t",
                      "int16_t","size_t","ssize_t","bool","void","int","char","long","short",
                      "unsigned","signed","float","double","const","struct","enum","static","inline"}
        for f, rel in inc_headers:
            try:
                content = open(f, errors="ignore").read()
            except OSError:
                continue
            # C 风格自由函数
            for m in re.finditer(r'^\s*(?:extern\s+)?[\w\s\*]+?\b([a-z][a-z0-9_]*)\s*\([^;]*\)\s*;', content, re.M):
                name = m.group(1)
                if name in seen or name in TYPE_WORDS or name in ("if", "for", "while", "return", "sizeof"):
                    continue
                seen.add(name)
                symbols.append(name)
            # C++ 风格: Class::method(  (类公共方法, 含返回类型跨行)
            if lang == "cpp":
                for m in re.finditer(r'\b([a-z][a-zA-Z0-9_]*)\s*\([^;{}]*\)\s*(?:const\s*)?[;{]', content):
                    name = m.group(1)
                    if name in seen or name in ("if", "for", "while", "return", "sizeof", "switch", "catch"):
                        continue
                    seen.add(name)
                    symbols.append(name)
    # (rust/go/python 的符号提取留待需要时扩展)

    return lib, list(dict.fromkeys(headers)), list(dict.fromkeys(symbols))

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", required=True, help="目标源码树")
    ap.add_argument("--scan-root", required=True, help="同发行版源码根")
    ap.add_argument("--lib", default="", help="库名, 如 security_conf")
    ap.add_argument("--headers", default="", help="头/模块名, 逗号分隔, 如 libsecurity_conf.h")
    ap.add_argument("--symbols", default="", help="导出符号, 逗号分隔")
    ap.add_argument("--lang", default="c", choices=list(LANG_CONF)+["cpp"], help="目标语言 (c=c/c++)")
    ap.add_argument("--pkg-pattern", default="*.src", help="包目录命名模式 (glob)")
    ap.add_argument("--exclude-pkgs", default="", help="额外排除的包名, 逗号分隔")
    ap.add_argument("--auto", action="store_true",
                    help="自动从目标树提取 lib/headers/symbols (替代手工传入)")
    args = ap.parse_args()

    # ---- --auto 模式: 从目标树自动提取身份信息 ----
    if args.auto:
        auto_lib, auto_headers, auto_symbols = auto_extract(args.target, args.lang)
        if not args.lib: args.lib = auto_lib
        if not args.headers: args.headers = ",".join(auto_headers)
        if not args.symbols: args.symbols = ",".join(auto_symbols)
        print(f"[auto] 提取: lib={args.lib or '(无)'} headers={args.headers or '(无)'} symbols={args.symbols or '(无)'}")

    conf = LANG_CONF[args.lang]
    lib = args.lib
    headers = [h.strip() for h in args.headers.split(",") if h.strip()]
    symbols = [s.strip() for s in args.symbols.split(",") if s.strip()]
    impl_names = collect_impl_basenames(args.target)
    target_name = os.path.basename(args.target.rstrip("/"))
    exclude = set(args.exclude_pkgs.split(",")) if args.exclude_pkgs else set()

    # 枚举包目录
    pkg_pat = re.compile(args.pkg_pattern.replace(".", r"\.").replace("*", ".*"))
    pkgs = [p for p in sorted(os.listdir(args.scan_root))
            if os.path.isdir(os.path.join(args.scan_root, p)) and
            (pkg_pat.match(p) or p not in (target_name,)) and p not in exclude]
    print(f"扫描 {len(pkgs)} 个包目录 (pattern={args.pkg_pattern}, lang={args.lang})")

    consumers = []
    for pkg in pkgs:
        pkg_dir = os.path.join(args.scan_root, pkg)
        src = find_src_root(pkg_dir)
        if not os.path.isdir(src):
            continue
        evidence = {"link": [], "header": [], "symbol": []}

        # 1. 链接声明 (排除审计报告/产物目录 — 报告文本会假命中库名)
        #    匹配: -l<lib> / AC_CHECK_LIB / <lib>.la / lib<lib>.so / pkg-config <lib>
        if lib:
            for pat in [rf"AC_CHECK_LIB\(\[?{lib}\]?", rf"(^|[^a-zA-Z0-9_-])-l{lib}\b",
                        rf"{lib}\.la\b", rf"lib{lib}\.so", rf"pkg-config.*\b{lib}\b"]:
                for f in rg(pat, src, conf["link_files"]):
                    rel = os.path.relpath(f, pkg_dir)
                    if any(bad in rel for bad in ("exp-audit", "reports", "REPORT", "audit", "review", ".pi")):
                        continue
                    evidence["link"].append(rel)

        # 2. 头/模块引用
        for h in headers:
            for f in rg(conf["header_pat"](h), src, conf["header_globs"]):
                evidence["header"].append(os.path.relpath(f, pkg_dir))

        # 3. 符号多形态: 调用 / 取址 / 赋值 / 方法表 (排除审计产物)
        for sym in symbols:
            for f in rg(rf'\b{re.escape(sym)}\s*\(|\b{re.escape(sym)}\b\s*=|&\s*{re.escape(sym)}\b|\.{re.escape(sym)}\s*=', src, conf["src_globs"]):
                rel = os.path.relpath(f, pkg_dir)
                if any(bad in rel for bad in ("exp-audit", "reports", "REPORT", "audit", "review", ".pi")):
                    continue
                evidence["symbol"].append(rel)

        if evidence["link"] or evidence["header"] or evidence["symbol"]:
            # 排除目标复制品: 消费者树含目标实现文件 → 复制品
            impl_hits = [f for f in _glob.glob(os.path.join(src, "**", "*"), recursive=True)
                         if os.path.basename(f) in impl_names]
            if impl_hits:
                print(f"  (跳过 {pkg}: 含目标实现文件 {[os.path.basename(f) for f in impl_hits[:4]]}, 复制品)")
                continue
            consumers.append({
                "package": pkg,
                "src_root": src,
                "evidence": evidence,
                "confidence": "high" if evidence["link"] else ("medium" if evidence["symbol"] else "low"),
            })

    for c in consumers:
        print(f"\n[{'✅' if c['confidence']=='high' else '⚠️'} {c['confidence']}] {c['package']}")
        print(f"  src_root: {c['src_root']}")
        for k in ("link", "header", "symbol"):
            if c["evidence"][k]:
                print(f"  {k}: {c['evidence'][k][:3]}")

    out = "consumers.json"
    with open(out, "w") as f:
        json.dump({"target": args.target, "consumers": consumers}, f, ensure_ascii=False, indent=1)
    print(f"\n输出: {out} ({len(consumers)} 个消费者)")

if __name__ == "__main__":
    main()
