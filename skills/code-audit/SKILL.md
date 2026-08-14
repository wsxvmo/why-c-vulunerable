---
name: code-audit
description: C/C++/Shell/Python static source code audit methodology — per-CWE pattern libraries, sink lists, detection, confirmation and false-positive elimination. Replaces web-pentest for the C/C++/Shell/Python audit pipeline.
---

# Code Audit Methodology (C/C++ / Shell / Python)

Static source code audit methodology for the C/C++/Shell/Python pipeline. Every class follows the same 5-part structure: **Checklist → Techniques → Detection → Confirmation → False-Positive elimination**.

## Toolchain

| Tool | Role |
|------|------|
| `codebase-memory-mcp` | Whole-repo graph: entry points, call chains (`trace_path --mode data_flow`), architecture. Index first. |
| `joern` (joern-parse / joern-scan / queries) | Mandatory engine: CPG build (fuzzy, no target compilation), querydb sweep, taint queries. Output = candidates. |
| `lsp_*` (pi-lsp → clangd / bash-language-server) | Semantic verification: definitions, references, diagnostics. Confirms symbols are real. |
| `grep`/`read` | Manual hop-by-hop verification and evidence collection. |
| sanitizers (gcc/clang `-fsanitize=address,undefined`, valgrind) | VALIDATE stage: self-contained repro triggers. Target project is never compiled. |

**Rules:**
- Never compile the target project. Only self-contained repro files extracted from it.
- Joern/clangd output = candidates. Every finding needs hop-by-hop evidence (entry → sink).
- Joern is the CPG engine here. No CodeQL. No web semantics.

## 1. C/C++ — Memory Safety Classes

### 1.1 buffer-overflow (CWE-120/121/122/787)

**Checklist:**
- [ ] All `strcpy`/`strcat`/`sprintf`/`vsprintf`/`gets`/`scanf` calls — unbounded copies
- [ ] All `memcpy`/`memmove`/`bcopy` calls — size argument source (is it attacker-controlled?)
- [ ] All `strncpy`/`snprintf`/`strncat` uses — **n** computed from attacker data? off-by-one?
- [ ] Stack arrays indexed by loop variables or computed offsets
- [ ] `alloca` with attacker-controlled size
- [ ] Implicit conversions: `int`→`size_t`, `unsigned` wraparound before copy

**Techniques:**
```
joern: cpg.call.name("(strcpy|strcat|sprintf|gets|memcpy|memmove|alloca).*").l
grep:  strcpy\(|strcat\(|sprintf\(|vsprintf\(|gets\(|memcpy\(|alloca\(
```
Then for each hit: trace the size/length argument to its source (Joern `reachableBy` / codebase-memory `trace_path --mode data_flow`).

**Detection:** any path where a copy size or destination index is derived (directly or through arithmetic) from attacker-controlled input (network, argv, file, env, DBus) without a validated bound.

**Confirmation:** self-contained repro with ASAN:
```c
// extract the vulnerable copy + minimal trigger, compile with:
// gcc -fsanitize=address,undefined -g repro.c -o repro && ./repro
// expect: ERROR: AddressSanitizer: stack-buffer-overflow / heap-buffer-overflow
```

**False positives:** strlen-bounded copies where n is computed correctly; compiler-inserted bounds checks (`_FORTIFY_SOURCE`); copies where the size is a compile-time constant ≤ destination capacity.

### 1.2 out-of-bounds-read (CWE-125)

**Checklist:**
- [ ] Array/pointer reads with attacker-controlled index (including negative)
- [ ] Off-by-one reads in loops (`<=` vs `<`, `len` vs `len-1`)
- [ ] Reads past NUL terminator when using `strlen` results as index
- [ ] `memcmp`/`memchr`/`read` with over-large n

**Detection:** attacker-controlled index into a fixed-size buffer; loop bounds that can exceed array length by 1+.

**Confirmation:** ASAN `heap-buffer-overflow READ` / `global-buffer-overflow` / valgrind `Invalid read`.

### 1.3 use-after-free (CWE-416)

**Checklist:**
- [ ] All `free()` call sites — is the pointer used afterwards (same function or via stored reference)?
- [ ] Objects freed in one path, used in another (error paths, refcount bugs)
- [ ] Global/static pointers to freed memory
- [ ] Double-owned pointers (two structs point to same heap block, one frees)

**Techniques:**
```
joern: cpg.call.name("free").l   → then look for uses of the freed variable after the call
```

**Detection:** use of a pointer after `free()` on any reachable path; missing refcount decrement/increment.

**Confirmation:** ASAN `heap-use-after-free` (READ/WRITE of size N at address...) with the UAF stack.

**False positives:** free at end of function with no later use; `free(NULL)` patterns; intentionally cached-but-reset pointers.

### 1.4 double-free (CWE-415)

**Checklist:**
- [ ] Two paths both reach `free(p)` for the same `p` (error handling + normal path)
- [ ] `free` in a loop + `free` after the loop
- [ ] Realloc patterns: `p = realloc(p, ...)` on failure leaves p valid → later double free

**Confirmation:** ASAN `attempting double-free` / valgrind `Invalid free() / delete`.

### 1.5 integer-overflow (CWE-190/191)

**Checklist:**
- [ ] `size_t`/`int` arithmetic feeding `malloc`/`memcpy`/array index: `n * m`, `n + 1`, `len - 1`
- [ ] Signed/unsigned mixing, truncation (`long`→`int`, `size_t`→`int`)
- [ ] `strlen(x) + 1` before allocation/copy (off-by-one on empty input)
- [ ] Loop counters that overflow

**Detection:** arithmetic on attacker-controlled lengths that can wrap before being used as allocation size or copy bound.

**Confirmation:** UBSAN `runtime error: signed integer overflow` / ASAN `allocation-size-too-big`; or repro computing `0xffffffff * 2 = 0` path.

**False positives:** values proven bounded by earlier validation (e.g. `if (n > 100) return`); `int` arithmetic on constants.

### 1.6 null-deref (CWE-476)

**Checklist:**
- [ ] `malloc`/`calloc`/`realloc` return not checked → immediate deref
- [ ] `strdup`/`asprintf`/`getline` return not checked
- [ ] Function returns `NULL` on error, caller derefs without check (CWE-690)
- [ ] `pthread_*` / DBus / config lookup returns NULL

**Confirmation:** repro triggers NULL deref → SIGSEGV in ASAN build.

**False positives:** paths where NULL is impossible by construction; `assert`-guarded code (note: asserts compile out with NDEBUG!).

### 1.7 uninitialized-use (CWE-457)

**Checklist:**
- [ ] Stack variables declared, conditionally initialized, then read
- [ ] Struct fields not zeroed (`calloc` vs `malloc` mismatch)
- [ ] Partially initialized structs passed to functions that read all fields

**Detection:** clangd diagnostics + `-Wmaybe-uninitialized` warnings; manual conditional-init analysis.

**Confirmation:** valgrind `Conditional jump or move depends on uninitialised value(s)` / MSAN (if available).

### 1.8 format-string (CWE-134)

**Checklist:**
- [ ] `printf`/`fprintf`/`sprintf`/`snprintf`/`syslog` with a **non-literal** format argument (variable, function param, config value)
- [ ] `%n` write primitive if attacker controls format

**Detection:** format argument is not a string literal and flows from attacker input.

**Confirmation:** repro with `%x%x%x%x` leaks stack / `%n` crashes ASAN build.

**False positives:** format is compile-time literal; `"%s", var` correct two-arg form.

## 2. C/C++ — Injection, Paths, Resources

### 2.1 command-injection (CWE-78)

**Checklist:**
- [ ] `system()` / `popen()` / `execl*` with non-literal command string
- [ ] Command assembled by string concat: `snprintf(cmd, "%s %s", prog, user_input)`
- [ ] Shell metacharacters reachable: `; | & $ ` \n`
- [ ] `posix_spawn` with shell-invoked argv

**Confirmation:** repro where attacker input breaks out of the command context (e.g. `; id` → output contains uid).

### 2.2 path-traversal (CWE-22/23)

**Checklist:**
- [ ] File open/write paths built from attacker input: `open()`, `fopen()`, `openat()`, `rename()`, `unlink()`
- [ ] Missing `..` / absolute path sanitization
- [ ] Confined-path escapes: `chroot` without `chdir` (classic chroot escape)

**Confirmation:** repro writes/reads a file outside the intended directory.

### 2.3 symlink-follow (CWE-59)

**Checklist:**
- [ ] Writing to predictable paths in world-writable dirs (`/tmp/<fixed-name>`) — attacker pre-creates symlink
- [ ] `open()` without `O_NOFOLLOW` on attacker-influenced paths
- [ ] `access()` + `open()` TOCTOU with symlink swap

**Confirmation:** repro: pre-create symlink at target path → target's file gets overwritten / content read.

### 2.4 unsafe-temp-file (CWE-377/378/379)

**Checklist:**
- [ ] `tmpnam`/`mktemp`/`tempnam` (insecure) instead of `mkstemp`/`mkdtemp`
- [ ] Fixed temp paths in `/tmp` with `fopen("w")`
- [ ] Temp files created with 0666/0777 without umask

**Confirmation:** symlink attack or predictable-name collision repro.

### 2.5 race-condition / toctou (CWE-362/367)

**Checklist:**
- [ ] `access(path)` then `open(path)` / `stat` then `write` on attacker-controllable path
- [ ] Check permission then act on a path that can be swapped (symlink, rename)
- [ ] Multi-threaded shared state without locks (signal handlers + main thread)
- [ ] `signal()` handlers doing non-async-signal-safe work

**Confirmation:** loop-based repro racing `rename`/`symlink` swap; ASAN or file-content evidence.

## 3. C/C++ — Privilege & Access

### 3.1 access-control (CWE-284/862/863)

**Checklist:**
- [ ] DBus method handlers: **is there `sd_bus_creds_get_uid()` / `dbus_message_get_sender()` + authorization check?** (see DBus section)
- [ ] Check-then-use object mismatch (checked resource A, operated on B)
- [ ] Missing owner/group verification on file access
- [ ] IPC / socket handlers without peer credential checks (`SO_PEERCRED`)

**Confirmation:** repro as unprivileged user successfully calls the guarded operation.

### 3.1a spoofable-identity (CWE-287/269) — 身份信任边界

Highest-yield class in local-audit targets: the authorization decision trusts an **identity that the caller can forge**. Classic Linux identity sources and their forgeability:

| Identity source | Forgeable by caller? | Notes |
|---|---|---|
| `pid` / `ppid` | no (kernel-owned) | but the *meaning* of a pid is racy (reuse) |
| uid/gid of caller | no (kernel-owned) | forge only via setuid bugs |
| `argv[0]` / full cmdline (`/proc/pid/cmdline`) | **YES** | caller writes its own argv before exec — any check parsing cmdline/argv is attacker-controlled |
| process name (`comm`, `prctl(PR_SET_NAME)`) | **YES** | same as argv |
| env vars (incl. `LD_PRELOAD`, `LD_LIBRARY_PATH`) | **YES** | env-based "identity" checks are not identity checks at all |
| service name on the bus (D-Bus well-known name) | **YES (race)** | NameAcquire race / squatting before the real owner |
| executable path of the caller | partial | real path is kernel-owned, but wrappers/symlinks change the *reported* path |
| file the caller opens / loads (plugins, scripts) | **YES** | loading attacker-influenced content under a trusted name |

**Checklist:**
- [ ] For EVERY authorization decision: what exactly is being trusted — a kernel credential, or caller-controlled data (argv/cmdline/env/name)?
- [ ] grep whole codebase for `cmdline` / `argv[0]` / `prctl(PR_SET_NAME)` / `getprogname` / `__progname` — each is an identity input the caller controls
- [ ] `LD_PRELOAD` / `LD_LIBRARY_PATH` / `PATH` presence used as a trust signal? (e.g. "lib not preloaded ⇒ trusted") → invert it: attacker preloads and becomes trusted
- [ ] Components the *user* can launch that the daemon treats as privileged callers (user-launchable GUI apps, interpreters, wrappers)
- [ ] **Cache/state keyed by identity**: any cache (auth results, capability blobs, permission records) whose key omits uid/sid/pid dimension → cross-user inheritance. Key completeness is a security property, not a perf detail.
- [ ] Cache invalidation on identity change: setuid/setgid/exec paths that keep stale cache entries for the new identity

**Confirmation:** unprivileged repro that forges the identity (crafted argv, preload, name squat) and successfully passes the guarded check; or cache hit for another user's identity without authorization.

**False positives:** decisions that additionally verify a kernel credential (e.g. real uid) after parsing the forgeable string — string parsing alone is not authorization.

### 3.2 privilege-mgmt (CWE-250/269/271/272/273)

**Checklist:**
- [ ] setuid/setgid/seteuid/setresuid **return value not checked** (CWE-273 — most common!)
- [ ] Privilege not dropped before handling attacker input (CWE-250/272)
- [ ] Dropped privileges regained (saved uid retained, `seteuid` back without need)
- [ ] Daemons running as root that could run as nobody

```
grep: setuid\(|seteuid\(|setresuid\(|setgid\(|setegid\(|setregid\(
```
For each: is the return checked? is it a *permanent* drop (setuid vs seteuid)? what runs after?

**Confirmation:** repro: setuid binary with unchecked `setuid()` — non-root call fails silently, privileged operation continues. Or: input handling occurs before privilege drop.

### 3.3 permission-assignment (CWE-732/276)

**Checklist:**
- [ ] `open(path, O_CREAT, mode)` with mode ≥ 0666 (world-writable)
- [ ] `umask(0)` before creating files
- [ ] `chmod`/`fchmod` to 0777/0666 on sensitive files
- [ ] DBus `.conf` policy files: `context="default"` rules allowing privileged interfaces
- [ ] Config/log/state files with default permissive modes

**Confirmation:** repro: file created with world-writable mode; or DBus policy analysis showing any-user call path.

## 4. DBus / IPC 专项 (C/C++)

DBus system-bus services are a common local-privilege-escalation surface. Audit every service method:

**Checklist:**
- [ ] Find service registrations: `sd_bus_add_object_vtable` / `dbus_connection_register_object_path` / `g_dbus_connection_register_object`
- [ ] For EVERY method handler, check for credential verification:
  ```c
  // present? → authorized (verify it checks the RIGHT uid, not just any)
  sd_bus_query_sender_creds(...) / sd_bus_creds_get_uid(...)
  dbus_message_get_sender(...) + lookup sender's uid
  // absent? → any user on the system bus can invoke → CWE-862 access-control
  ```
- [ ] Policy files: `/etc/dbus-1/system.d/*.conf`, `/usr/share/dbus-1/system.d/*.conf`
  - `context="default"` allow rules for send_interface of privileged services → CWE-732
  - Missing `deny` for unprivileged users
- [ ] Name ownership: can unprivileged users claim the service name first? (NameAcquire race)
- [ ] After method dispatch: are per-argument checks done (path traversal via DBus string args)?

**Confirmation:** repro: `busctl --user/--system call <service> <path> <iface> <method>` as unprivileged user succeeds when it must not; or reads/writes attacker-chosen paths.

## 5. Shell — CWE-78 / temp / permissions

### 5.1 shell-injection (CWE-78)

**Checklist:**
- [ ] `eval` with non-literal content
- [ ] Command substitution `$(...)` / backticks with variables that can contain metachars
- [ ] String-built commands: `cmd="$BIN $USER_INPUT"` then `$cmd` / `sh -c "$cmd"`
- [ ] `find -exec` / `xargs` / `awk system()` with interpolated input
- [ ] Unquoted variable expansions in command position

**Detection:** variable used in a command context without quoting where its content includes user input.

**Confirmation:** repro: `USER_INPUT='; id'` → command executes.

### 5.2 path-traversal / unsafe-temp-file in shell

**Checklist:**
- [ ] `mktemp` without template or with fixed path; `> /tmp/$name` predictable
- [ ] `rm -rf $DIR` with unvalidated DIR (attacker sets DIR=/)
- [ ] `cp`/`mv` to paths derived from input without `--` separator (option injection: `--help` as filename)

### 5.3 permission-assignment in shell

**Checklist:**
- [ ] `umask` not set before redirecting output files
- [ ] `chmod 777` / `chown` misuse on sensitive files
- [ ] Scripts run from world-writable dirs (attacker plants same-name script → PATH hijack, CWE-426/427)

## 6. Python — Injection / Deserialization

### 6.1 eval-injection (CWE-95/94)

**Checklist:**
- [ ] `eval()` / `exec()` / `execfile()` with non-literal input
- [ ] `compile()` + `exec` of attacker data
- [ ] `functools`/`importlib` dynamic import from attacker-controlled names
- [ ] Jinja2/Mako template evaluation of user data

**Confirmation:** repro: `eval("__import__('os').system('id')")` executes.

### 6.2 unsafe-deserialization (CWE-502)

**Checklist:**
- [ ] `pickle.loads`/`pickle.load` on untrusted data
- [ ] `yaml.load` (not `yaml.safe_load`)
- [ ] `shelve` open on attacker-writable file
- [ ] `marshal`/`dill`/`cloudpickle` on untrusted bytes
- [ ] `jsonpickle` (dangerous by design)

**Confirmation:** repro with malicious pickle `__reduce__` → command execution.

### 6.3 command-injection (Python)

**Checklist:**
- [ ] `subprocess` with `shell=True` and non-literal command string
- [ ] `os.system` / `os.popen` / `os.spawn*` with concatenated input
- [ ] `subprocess.run(cmd_list)` where a list element contains metacharacters (list is NOT a safe boundary if element is `sh -c` input)
- [ ] `os.startfile` / `webbrowser.open` with attacker URL scheme

**Confirmation:** repro: `subprocess.run("echo " + inp, shell=True)` with `; id`.

### 6.4 path-traversal / temp in Python

**Checklist:**
- [ ] `open(path)` / `os.path.join` with attacker input and missing `..` handling
- [ ] `shutil.copy`/`os.rename` to attacker-influenced dest
- [ ] `tempfile` misuse: `NamedTemporaryFile(delete=False)` with fixed dir, or manual `open("/tmp/x", "w")`
- [ ] Zip-slip: `zipfile.extractall` on untrusted archive without member name validation

### 6.5 race-condition in Python

**Checklist:**
- [ ] check-then-use on files (`os.path.exists` → `open`) — TOCTOU
- [ ] `os.makedirs` + later chmod (permission race)
- [ ] Multi-threaded state without locks

## 6a. Rust — String Injection / unsafe / FFI / serde

Rust targets (daemons, policy engines, FFI libraries) have language-specific classes that the C/C++ sections do not cover. Pattern library from real audits (kysec-scene: 7 policy-injection sinks, unsafe transmute, FFI ABI mismatch, CString panic DoS, merge semantic inversion).

### 6a.1 format!-string-injection (CWE-94/74)

**Checklist:**
- [ ] Every `format!` / `format_args!` / `concat!` whose arguments include user-controlled `String`/`&str` fields (JSON-deserialized, argv, D-Bus args, env)
- [ ] DSL generators: `export_policy()` / `to_policy_*()` / `to_rule()` / `build_*_string()` functions that assemble structured language text (policy, SQL, XML, shell)
- [ ] **Differential index**: find where the codebase DOES escape (`replace('\\',"\\\\").replace('"',"\\\"").replace('\n'," ")` in one var builder) and ask why sibling builders don't — escaped vs unescaped inconsistency = missed sink
- [ ] Variable **names** vs **values**: name paths (e.g. hex-encoded var names decoded then interpolated) often skip escaping that value paths have
- [ ] Multi-line payloads: `\n` + `"` breakout, `#` comment injection into DSL

**Techniques:**
```
grep: format!\(.*self\. | format!\(.*\.scene|format!\(.*\.addon|format!\(.*\.subject|format!\(.*\.func
```
For each hit: trace the interpolated field to its source (JSON field / D-Bus arg / argv). Check whether a sibling builder escapes it.

**Detection:** user-controlled string reaches `format!` that produces text consumed by another parser (compiler/interpreter/DSL), with no escaping on the field.

**Confirmation:** self-contained Rust repro: deserialize malicious JSON → call `export_policy()` → inspect output for injected standalone line (line-level match, NOT substring `contains` — substring matches escaped literal text and false-positives).

**False positives:** fields proven constrained (enum, validated charset, length-capped to safe subset); the DSL parser rejects the injected syntax (verify with the actual compiler if available).

### 6a.2 unsafe-transmute (CWE-704)

**Checklist:**
- [ ] `std::mem::transmute` / `transmute_copy` call sites — what validation ran before it?
- [ ] `try_from_bytes` / `from_raw` patterns: length-only checks before reinterpreting bytes as structs
- [ ] Enum fields (op/perm/type/version) validated? All-0xFF payload accepted = missing field validation
- [ ] `#[repr(C)]` struct layouts: field order/size vs C header counterpart

**Confirmation:** feed length-correct but field-invalid bytes (e.g. 0xFF fill) → accepted (Some). Control: wrong length → rejected. Length-checked + content-unchecked = finding.

### 6a.3 CString/str unsafe-conversions (CWE-476/125)

**Checklist:**
- [ ] `CString::new(x).unwrap()` — NUL byte in x → panic; is x attacker-controlled (JSON `\u0000` survives serde)?
- [ ] `CStr::from_ptr` on fixed-size `[c_char; N]` slices — scans past N if no NUL; full-buffer input = OOB read
- [ ] `std::ptr::read` on FFI structs — size mismatch vs C side = deterministic OOB
- [ ] `forget()` / `into_raw` ownership handoffs — leak, dangling, cross-allocator free
- [ ] `.unwrap()` / `.expect()` on D-Bus/parsing results reachable from attacker input

**Confirmation:** NUL-injected JSON → CString::new → panic (lib-level repro); full-buffer c_char array → CStr::from_ptr reads past end (ASAN or graceful-Err analysis).

### 6a.4 serde-deserialization (CWE-502/20)

**Checklist:**
- [ ] `serde_json` / `bincode` / `toml` deserialization of attacker-writable files or D-Bus bytes — field validation after parse?
- [ ] `\u0000` escapes: JSON NUL survives into Rust String (feeds 6a.3)
- [ ] Untagged enums / internally-tagged enums: unknown variant handling
- [ ] Missing `#[serde(deny_unknown_fields)]` on policy/config structs
- [ ] bincode `Vec` length fields from untrusted bytes — allocation bombs

### 6a.5 semantic-inversion / doc-vs-impl (CWE-670)

**Checklist:**
- [ ] Merge/combine functions where the doc comment states one precedence but code does the opposite (`*self = other.to_owned()` while doc says "keep self")
- [ ] Unit tests asserting the WRONG behavior (test encodes the bug)
- [ ] Call-site argument order vs documented semantics (`--base-on X --add Y` but impl lets Y win)

**Confirmation:** run the real binary's merge/combine with conflicting inputs; parse the OUTPUT FILE (system artifact) — not script-printed success.

## 6b. DSL / Policy-Language Injection (generic)

Applies wherever user-controlled strings are interpolated into a structured language that is later compiled/interpreted (KSAF policy, SELinux policy, iptables rules, SQL, XML, templates). Root cause is always: **unescaped interpolation into a language with metacharacters**.

**Checklist:**
- [ ] Enumerate ALL DSL generation functions: `to_policy*`, `export*`, `build_rule*`, `to_sql`, `render*`, `format_*`
- [ ] For each: which fields are user-controlled? which metacharacters does the DSL treat specially (`"` `\n` `#` `;` `'` backtick `$`)?
- [ ] Find the escaping helper if one exists (e.g. `build_string_list_var` escapes quote/backslash/newline) — **differential**: every sibling generator without the same escaping is a candidate
- [ ] Check BOTH value fields AND name/identifier fields (names often bypass value escaping)
- [ ] Encoding-based bypass: hex/base64/percent-encoding of the payload that the generator decodes before interpolation (e.g. `hex_decode(var_name)`)
- [ ] Structural injection: can the payload close the current statement and open a new one (`%ENDSEC`, `}`, `;`)?
- [ ] Does the downstream compiler/parser re-validate? (often syntax-only — injection that parses = effective)

**Techniques:**
```
grep: to_policy_rule|to_policy_rules|export_policy|add_var_def|to_var_call|curr_section_name
```
Systematically test EVERY VariableTypes variant / module generator, not just the obvious ones (audit blind-spot: kidctl sub-module generators missed until pointed out).

**Confirmation:** inject payload into the JSON/config, run the real generator, parse the OUTPUT (file or returned text) and show the injected standalone statement. Line-level detection, not substring.

## 6c. C ABI Export Surface Audit

Shared libraries exposing `extern "C"` / `#[no_mangle]` / `dlopen`-able symbols create a trust boundary: the library assumes callers are privileged/trusted, but nothing enforces it. Audit every exported function as a standalone API.

**Checklist:**
- [ ] Enumerate ALL exports: `nm -D <lib>`, `#[no_mangle] pub extern "C" fn`, `extern "C" fn` in headers
- [ ] NULL pointer guards: every `*const c_char` / `*mut T` param — `bail_any_null!` / `is_null()` before use? (systematic sweep: count guarded vs unguarded siblings — missing guards = candidates)
- [ ] `count`/`len` params: bounds-checked before `slice::from_raw_parts` / `*ptr.add(i)` loops? (inflated count = OOB read)
- [ ] Struct ABI: C header struct vs Rust `#[repr(C)]` struct — same size/layout? (C 4228B vs Rust 4232B = 4B OOB read on every call)
- [ ] Ownership handoff: `into_raw`/`forget`/`alloc` vs caller `free()` — cross-allocator UB, leaks, dangling empty-vec pointers (should return NULL on empty)
- [ ] Caller identity: does the export verify WHO calls it (uid/path/env), or assume trust? env-only checks (LD_PRELOAD absence) are not identity checks
- [ ] Panic across FFI boundary: `.unwrap()` in `extern "C"` — panic = abort of the CALLER process

**Techniques:**
```
# systematic sweep of string-param exports and count-param exports
nm -D lib.so | grep " T "
grep -rn 'pub extern "C" fn' src/  # + check bail_any_null in body
```

**Confirmation:** fork-based test: call the export with NULL / inflated count / oversized buffer from a test program → observe SIGSEGV in the CHILD (caller process), parent survives. Record whether the crash lands in the caller or in a privileged service.

**Critical reachability gate (do not skip):** a real defect in an export is NOT a vulnerability unless a privileged process calls it with attacker-controlled args. Check: (1) does the daemon/service call this export? (2) is the symbol referenced (`nm -D` U-references) by any other component? (3) does the crash/leak land in the attacker's own process (self-DoS only)? Exports that no component calls, or whose failure only crashes the caller, are KILLED — mechanism real, no cross-boundary impact.

### 6d. patch-diff-audit (补丁绕过审计 / KVE 补丁一致性)

When a previous CVE/KVE fix exists for the target (vendor patch, backported fix, security-enhancement patch), the highest-value hunt is auditing the FIX itself — shipped fixes are routinely incomplete: they cover the reported path, not the pattern.

**Checklist:**
- [ ] Obtain the patch (src.rpm diff, git log, vendor advisory). Extract the **fix pattern** — not the diff: what invariant does it enforce? (canonical path, `O_NOFOLLOW`, escaping, uid check, size bound)
- [ ] **Sibling sweep**: find every other site with the same vulnerable pattern and check whether the patch touched it. Patches that fix one call site and miss the sibling are the norm, not the exception.
- [ ] **Interface sweep**: the patch fixed the CLI path — did it fix the GUI/D-Bus/API path? Same semantic operation reachable through another interface is the classic miss.
- [ ] **Constructive bypasses** for each fix class:
  - path validation: symlink at the final component (parent-only validation), `..` normalization differences (`canonicalPath` vs manual strip), double slashes, hardlinks, procfs aliases
  - escaping: alternate metacharacters not in the fix's deny-set (newline vs quote vs comment char), encoding the filter decodes after check (hex/base64/percent)
  - bounds: fix caps one input, sibling arithmetic still overflows; fix adds `+1`, off-by-one remains
  - auth: fix checks presence of a credential, not its value; fix checks a forgeable identity (see 3.1a)
  - TOCTOU: fix validates, then a re-checkable window remains between check and use
- [ ] Version-diff: compare the audited source against the *fixed* upstream release — the delta itself is a candidate list (every removed check is a regression, every added check marks where a bug lived)
- [ ] Partial backports: fix landed in a newer branch but the shipped package is older — audit the shipped version against the fixed one

**Confirmation:** run the fixed build with the constructive bypass (symlink pre-created, alternate metachar, sibling interface) and show the fix is defeated; or show the sibling site still vulnerable in the fixed tree.

**False positives:** fixes that are actually pattern-wide (escaped in a shared helper, centralized path checker) — verify the helper is the only path, no direct call sites bypass it.

## 7. Cross-cutting

### 7.1 resource-leak / memory-leak (CWE-401/404/775)

**Checklist:**
- [ ] `malloc` without matching `free` on error/early-return paths
- [ ] `open()`/`fdopen` without `close` on all paths
- [ ] DBus connections / pthreads / file handles leaked in loops
- [ ] Python: unclosed file handles, `subprocess` pipes not drained

**Confirmation (functional):** valgrind leak summary shows definite loss; fd exhaustion repro.

### 7.2 crypto-weakness (CWE-327/328)

**Checklist:**
- [ ] MD5/SHA1 for security purposes (not checksums)
- [ ] Hardcoded keys/passwords/salts
- [ ] `rand()`/`random` for security decisions (need CSPRNG: `getrandom`, `arc4random`, `secrets`)
- [ ] ECB mode, zero IV, weak KDF (single-round SHA for passwords)

### 7.3 info-disclosure (CWE-200)

**Checklist:**
- [ ] Stack traces / debug output with sensitive data (paths, pointers, env)
- [ ] Error messages leaking file existence, user existence, internal paths
- [ ] World-readable files containing secrets (permission-assignment interaction)
- [ ] Logging of passwords/tokens

## 8. Entry-point inventory (RECON output)

When mapping the target, enumerate by language:

| Language | Entry points |
|----------|-------------|
| C/C++ | `main()` + argv parsing, network callbacks (accept/recv), file parsers, DBus method handlers, shared-library exported API, signal handlers, plugin/dlopen entry, environment consumers (getenv) |
| Shell | script entry with `$1..$n`/`$@`, sourced config files, hooks (cron, udev, systemd ExecStart), `find -exec` callbacks |
| Python | `__main__` / argparse, web framework routes (Flask/Django), RPC/message consumers, plugin loading (entry_points), config/env consumers, `pickle`/`json` loaders |

## 9. Confirmation standards (VALIDATE stage)

| Class | Confirm by |
|-------|-----------|
| buffer-overflow / OOB-read / UAF / double-free | ASAN/valgrind error pointing at the sink |
| integer-overflow | UBSAN overflow report, or arithmetic wrap demonstrated |
| null-deref / uninitialized-use | ASAN/MSAN/valgrind or deterministic SIGSEGV on trigger input |
| command/shell/eval injection | injected command output visible OR deterministic side effect |
| path-traversal / symlink / temp | 2+ known files read/written outside intended dir |
| access-control / privilege / permission | unprivileged repro succeeds / file mode observed |
| unsafe-deserialization | code execution via crafted object |
| format-string | `%n`/`%x` observable effect in repro |

**If a class cannot be repro'd locally** (needs kernel, hardware, network peer): record `INCOMPLETE: blocked: no sanitizer trigger` — do not kill.

## 10. Kill taxonomy (止损清单)

Most candidate findings die in a small set of recurring ways. Recognize these early and stop spending trace/validate budget on them. A finding dies for ONE reason; classify it explicitly before killing.

| Kill class | Signature | Action |
|---|---|---|
| KILL-1 unreachable | static defect real, but the call chain / build flag / hook registration doesn't exist in the shipped configuration (feature compiled out, hook not registered, interface not exported) | verify build config + callers ONCE, then kill fast |
| KILL-2 already-fixed | target version contains the official patch (BUG# in changelog, fix in newer release) | check changelog/BUG references BEFORE deep diving a suspicious function |
| KILL-3 no-gain | defect real but an equivalent existing mechanism already grants the same outcome (per-task cache equals the bypass; another API already allows it) | compare against the attacker's existing capabilities — no capability crossing = no finding |
| KILL-4 self-attack | the "victim" is the attacker's own process / own data / own session (loading own .so, own config, own temp file) | require a privilege/trust boundary crossing; "real but no boundary crossing" is not a finding |
| KILL-5 disproven | dynamic PoC shows the trigger cannot fire (kernel timing, LSM hook order, language semantics) | write the disconfirmation first — it is cheaper than the confirmation |

**The 30-second pre-trace gate (apply BEFORE any deep TRACE):**
1. Does any caller outside the attacker's own process reach this code with attacker-controlled data? (no ⇒ KILL-1/KILL-4)
2. Is the fix already in the shipped version? (yes ⇒ KILL-2)
3. Does the outcome cross a privilege/trust boundary the attacker lacks? (no ⇒ KILL-3/KILL-4)
4. If 1-3 pass, the finding earns a TRACE budget. If any fails, kill with the reason recorded.

**Why this matters:** in production audits the majority of candidates are KILL-1..5. The difference between a fast audit and a slow one is not finding more — it is killing the dead ones in minutes instead of hours.
