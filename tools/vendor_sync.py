#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 CactOS Project

"""vendor_sync.py — refresh the vendored third-party trees from their upstreams.

The kernel vendors six third-party trees (each has an UPSTREAM.md next to it).
None is verbatim upstream: every one is upstream *pruned* of what the kernel does
not build and *patched* in a few recorded places.  So "sync" means: fetch the
upstream ref, re-apply the recorded patches, and diff the result against what is
committed here.

    tools/vendor_sync.py list                     # trees, upstream refs, patch counts
    tools/vendor_sync.py check [tree ...]         # fetch, re-apply, diff vs the tree
    tools/vendor_sync.py update <tree> [...]      # rewrite the tree from upstream
    tools/vendor_sync.py check --refresh rustls   # ignore the fetch cache

`check` never writes to the repository.  `update` does, so it refuses to run on a
dirty tree and prints a summary to review before `git add`.  A patch that no
longer applies is reported loudly instead of being dropped silently.

Fetches are cached under $XDG_CACHE_HOME/cact-vendor-sync and reused; pass
--refresh to re-fetch.  Network notes for this machine: crates.io/static.crates.io
are blocked, so crates come from the USTC mirror; github.com and git.kernel.org
work.  Nothing here runs during a normal build.
"""

from __future__ import annotations

import argparse
import difflib
import os
import re
import shutil
import subprocess
import sys
import tarfile
import urllib.request

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TMP = os.path.join(
    os.environ.get("XDG_CACHE_HOME", os.path.expanduser("~/.cache")), "cact-vendor-sync"
)
MIRROR = "https://mirrors.ustc.edu.cn/crates.io/api/v1/crates"
FRESH = False

# --------------------------------------------------------------------------
# Manifest: one entry per vendored tree.
#
#   dest    where the tree lives in the repo
#   origin  how to fetch upstream:
#             git   -> url, ref (tag/branch; "HEAD" = remote default branch,
#                      unpinned), optional sparse path list, optional subdir
#             crate -> name + version, from the USTC mirror
#   take    if set, only these upstream paths are vendored (1:1 layout)
#   map     if set, [upstream_path, repo_path] pairs (layout differs); a
#           directory maps to a directory
#   drop    upstream paths not vendored, relative to the *repo* layout
#   keep    repo paths that are CactOS's own: never compared, never deleted
#   manual  repo paths kept as ours; `check` reports how far they have drifted
#           from current upstream, `update` never rewrites them
#   spdx    {suffix: licence} - add `// SPDX-License-Identifier:` to matches
#   rewrite_linux_includes
#           if set, `<linux/X.h>` in every .c/.h becomes the path to
#           <this dir>/X.h relative to the file (zstd's compat/ shims)
#   edits   ordered literal substitutions re-applied after each fetch
# --------------------------------------------------------------------------
MANIFEST: dict[str, dict] = {
    "rustls": {
        "dest": "Cact/crypto/vendor/rustls-0.23.40",
        "origin": {"kind": "git", "url": "https://github.com/rustls/rustls",
                   "ref": "v/0.23.40"},
        # the repo root minus the workspace members we do not use and the test
        # fixtures (several MB of .der/.bin)
        "take": [".cargo", ".github", ".gitignore", ".lycheeignore",
                 ".rustfmt.toml", ".rustfmt.unstable.toml", ".taplo.toml",
                 "Cargo.toml", "LICENSE", "LICENSE-APACHE", "LICENSE-ISC",
                 "LICENSE-MIT", "README.md", "rustls"],
        "drop": ["rustls/src/testdata", "rustls/tests/data"],
        "spdx": {".rs": "Apache-2.0 OR ISC OR MIT"},
        "manual": ["rustls/Cargo.toml", "rustls/build.rs"],
        "edits": [
            {"file": "rustls/src/lib.rs",
             "find": "mod conn;\n",
             "replace": "/// Connection APIs: the shared connection state and the client/server halves.\npub mod conn;\n",
             "note": "cact_crypto/cact_net reach conn from outside the crate"},
            {"file": "rustls/src/conn.rs",
             "find": "pub(crate) mod unbuffered;\n",
             "replace": "pub mod unbuffered;\n",
             "note": "cact_crypto/cact_net reach unbuffered from outside the crate"},
        ],
    },
    "rustls-webpki": {
        "dest": "Cact/crypto/vendor/rustls-webpki",
        "origin": {"kind": "git", "url": "https://github.com/rustls/webpki",
                   "ref": "v/0.103.11"},
        "take": [".flake8", ".gitattributes", ".github", ".gitignore",
                 "Cargo.toml", "LICENSE", "README.md", "src"],
        "drop": [],
        "spdx": {".rs": "ISC"},
        "manual": ["Cargo.toml"],
        "edits": [
            {"file": "src/lib.rs",
             "find": '#[cfg(any(feature = "std", test))]\nextern crate std;\n\n',
             "replace": "",
             "note": "no_std: the kernel has no std to link"},
        ],
    },
    "rustls-pki-types": {
        "dest": "Cact/crypto/vendor/rustls-pki-types",
        "origin": {"kind": "crate", "name": "rustls-pki-types", "version": "1.12.0"},
        "take": None,
        "drop": [".gitignore", "tests"],
        "spdx": {".rs": "MIT OR Apache-2.0"},
        "manual": [".cargo-checksum.json"],
        "edits": [],
    },
    "zstd": {
        "dest": "Cact/drivers/zstd",
        "origin": {"kind": "git", "url": "https://github.com/torvalds/linux",
                   "ref": "v7.3-rc4",
                   "sparse": ["lib/zstd", "lib/xxhash.c", "include/linux/zstd.h",
                              "include/linux/zstd_lib.h", "include/linux/zstd_errors.h",
                              "include/linux/xxhash.h"]},
        "map": [["lib/zstd/common", "common"],
                ["lib/zstd/compress", "compress"],
                ["lib/zstd/decompress", "decompress"],
                ["lib/xxhash.c", "xxhash.c"],
                ["include/linux/zstd.h", "compat/zstd.h"],
                ["include/linux/zstd_lib.h", "compat/zstd_lib.h"],
                ["include/linux/zstd_errors.h", "compat/zstd_errors.h"],
                ["include/linux/xxhash.h", "compat/xxhash.h"]],
        # Linux ships a few files we do not link (the module wrappers and the
        # build file); they map to the dest root and are dropped here
        "drop": ["decompress_sources.h", "Makefile", "zstd_common_module.c",
                 "zstd_compress_module.c", "zstd_decompress_module.c"],
        "keep": ["cact_zstd.c", "cact_zstd.h", "meson.build",
                 "compat/compiler.h", "compat/errno.h", "compat/kernel.h",
                 "compat/limits.h", "compat/math64.h", "compat/module.h",
                 "compat/printk.h", "compat/stddef.h", "compat/string.h",
                 "compat/swab.h", "compat/types.h", "compat/unaligned.h",
                 "UPSTREAM.md"],
        "spdx": {},
        "manual": [],
        "rewrite_linux_includes": "compat",
        "edits": [
            {"file": "compat/zstd.h", "find": "LINUX_ZSTD_H", "replace": "CACT_ZSTD_H",
             "all": True, "note": "guard renamed (it is no longer the Linux header)"},
            {"file": "xxhash.c",
             "find": "/*\n * xxHash - Extremely Fast Hash algorithm\n",
             "replace": "/*\n * SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only\n * xxHash - Extremely Fast Hash algorithm\n",
             "note": "upstream has no SPDX line here; CactOS adds one"},
            {"file": "compat/xxhash.h",
             "find": "/*\n * xxHash - Extremely Fast Hash algorithm\n",
             "replace": "/*\n * SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only\n * xxHash - Extremely Fast Hash algorithm\n",
             "note": "upstream has no SPDX line here; CactOS adds one"},
        ],
    },
    "drm-uapi": {
        "dest": "Cact/drivers/gpu/drm/uapi",
        "origin": {"kind": "git", "url": "https://github.com/torvalds/linux",
                   "ref": "v7.3-rc4", "sparse": ["include/uapi/drm"]},
        "map": [["include/uapi/drm/drm.h", "drm.h"],
                ["include/uapi/drm/drm_mode.h", "drm_mode.h"],
                ["include/uapi/drm/drm_fourcc.h", "drm_fourcc.h"]],
        "drop": [],
        "keep": ["drm_ioctl.h", "drm_types.h", "UPSTREAM.md"],
        # an ABI: CactOS's copies are older than this ref and adapted by hand, so
        # the tool shows the drift and a human merges it together with cact_drm
        "manual": ["drm.h", "drm_mode.h", "drm_fourcc.h"],
        "spdx": {},
        "edits": [],
    },
    "acpica-platform": {
        "dest": "Cact/drivers/acpi/include/platform",
        # Pinned to the ACPICA commit whose licence (BSD-2-Clause-Patent OR
        # GPL-2.0-only) is the one these files declare.  Upstream has since
        # moved to BSD-3-Clause OR GPL-2.0-only (see the UPSTREAM.md) - bumping
        # this SHA means updating the SPDX line in both files.
        "origin": {"kind": "git", "url": "https://github.com/acpica/acpica",
                   "ref": "bc7b8aad0613f03a968d93a92ea025a517936350"},
        "map": [["source/include/platform/acenv.h", "acenv.h"],
                ["source/include/platform/acintel.h", "acintel.h"]],
        "drop": [],
        "keep": ["UPSTREAM.md"],
        # tailored to this kernel by hand (width, asm macros, BREAKPOINT3); a
        # re-sync is a careful manual merge, not a copy
        "manual": ["acenv.h", "acintel.h"],
        "spdx": {},
        "edits": [],
    },
}


# --------------------------------------------------------------------------
# fetching
# --------------------------------------------------------------------------
def run(cmd: list[str], cwd: str | None = None) -> None:
    p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    if p.returncode != 0:
        sys.exit(f"failed: {' '.join(cmd)}\n{p.stderr}")


def fetch(name: str, tree: dict) -> str:
    o = tree["origin"]
    root = os.path.join(TMP, name, "src")
    crate_dir = os.path.join(root, f"{o['name']}-{o['version']}") if o["kind"] == "crate" else root
    if os.path.isdir(crate_dir) and not FRESH:
        return crate_dir
    shutil.rmtree(root, ignore_errors=True)
    os.makedirs(root, exist_ok=True)
    if o["kind"] == "crate":
        url = f"{MIRROR}/{o['name']}/{o['version']}/download"
        tarball = os.path.join(TMP, f"{o['name']}-{o['version']}.crate")
        with urllib.request.urlopen(url, timeout=300) as r, open(tarball, "wb") as f:
            shutil.copyfileobj(r, f)
        with tarfile.open(tarball, "r:gz") as t:
            t.extractall(root)  # unpacks <name>-<version>/ into root
        return crate_dir
    # A full commit SHA cannot be passed to `git clone --branch`; fetch it
    # explicitly instead.  Only used for refs we pin to a commit, which are all
    # non-sparse trees.
    if re.fullmatch(r"[0-9a-f]{40}", o.get("ref") or ""):
        if o.get("sparse"):
            sys.exit(f"{name}: a pinned SHA cannot be combined with a sparse checkout — "
                     "pin a tag instead, or drop the sparse list")
        run(["git", "init", "--quiet", root])
        run(["git", "-C", root, "remote", "add", "origin", o["url"]])
        run(["git", "-C", root, "fetch", "--quiet", "--depth", "1", "origin", o["ref"]])
        run(["git", "-C", root, "checkout", "--quiet", "FETCH_HEAD"])
        return root
    cmd = ["git", "clone", "--quiet", "--depth", "1"]
    if o.get("sparse"):
        cmd += ["--filter=blob:none", "--sparse"]
    if o.get("ref") and o["ref"] != "HEAD":
        cmd += ["--branch", o["ref"]]
    cmd += [o["url"], root]
    run(cmd)
    if o.get("sparse"):
        # --no-cone: the sparse list mixes directories and single files
        # (lib/xxhash.c, include/linux/zstd.h); cone mode cannot express that.
        run(["git", "-C", root, "sparse-checkout", "set", "--no-cone", *o["sparse"]])
    return root


def resolved_ref(name: str) -> str:
    """The commit the cached fetch sits on - what to record in UPSTREAM.md."""
    out = os.path.join(TMP, name, "src")
    p = subprocess.run(["git", "-C", out, "rev-parse", "HEAD"],
                       capture_output=True, text=True)
    return p.stdout.strip() if p.returncode == 0 else ""


# --------------------------------------------------------------------------
# staging: fetched upstream -> "what the vendored tree should look like"
# --------------------------------------------------------------------------
def read(path: str) -> str:
    with open(path, "rb") as f:
        return f.read().decode("utf-8", "surrogateescape")


def write(path: str, text: str) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "wb") as f:
        f.write(text.encode("utf-8", "surrogateescape"))


def copy_into(src_root: str, rel: str, stage_dir: str, dest_rel: str) -> None:
    src = os.path.join(src_root, rel)
    if os.path.isdir(src):
        for dirpath, _, filenames in os.walk(src):
            for fn in filenames:
                inner = os.path.relpath(os.path.join(dirpath, fn), src)
                write(os.path.join(stage_dir, dest_rel, inner),
                      read(os.path.join(dirpath, fn)))
    else:
        write(os.path.join(stage_dir, dest_rel), read(src))


def stage(name: str, tree: dict) -> tuple[str, list[str], list[str]]:
    src = fetch(name, tree)
    stage_dir = os.path.join(TMP, "stage")
    shutil.rmtree(stage_dir, ignore_errors=True)
    drop = {os.path.normpath(d) for d in tree.get("drop", [])}
    pruned: list[str] = []

    def wanted(rel: str) -> bool:
        if any(rel == d or rel.startswith(d + os.sep) for d in drop):
            pruned.append(rel)
            return False
        return True

    if tree.get("map"):
        for up, dest_rel in tree["map"]:
            copy_into(src, up, stage_dir, dest_rel)
        # drop anything the mapping pulled in that we do not vendor
        for dirpath, dirnames, filenames in os.walk(stage_dir, topdown=True):
            rel_dir = os.path.relpath(dirpath, stage_dir)
            for fn in filenames:
                rel = fn if rel_dir == "." else os.path.join(rel_dir, fn)
                if not wanted(rel):
                    os.remove(os.path.join(dirpath, fn))
    else:
        take = tree.get("take")
        for dirpath, dirnames, filenames in os.walk(src):
            dirnames[:] = [d for d in dirnames if d != ".git"]
            for fn in filenames:
                rel = os.path.relpath(os.path.join(dirpath, fn), src)
                if take and not any(rel == t or rel.startswith(t + os.sep) for t in take):
                    continue
                if wanted(rel):
                    write(os.path.join(stage_dir, rel), read(os.path.join(dirpath, fn)))

    applied, failed = [], []

    shim = tree.get("rewrite_linux_includes")
    if shim:
        for dirpath, _, filenames in os.walk(stage_dir):
            for fn in filenames:
                if not fn.endswith((".c", ".h")):
                    continue
                path = os.path.join(dirpath, fn)
                text = read(path)
                if "#include <linux/" not in text:
                    continue
                prefix = os.path.relpath(os.path.join(stage_dir, shim), dirpath)
                if prefix == ".":
                    prefix = ""
                else:
                    prefix += "/"
                write(path, re.sub(r"#include <linux/([A-Za-z0-9_]+\.h)>",
                                   lambda m: f'#include "{prefix}{m.group(1)}"', text))
        applied.append(f"<linux/X.h> -> ({shim}/X.h relative to each file)")

    for e in tree["edits"]:
        path = os.path.join(stage_dir, e["file"])
        text = read(path)
        if e["find"] not in text:
            failed.append(f"{e['file']}: {e['note']}")
            continue
        write(path, text.replace(e["find"], e["replace"], -1 if e.get("all") else 1))
        applied.append(f"{e['file']}: {e['note']}")

    for suffix, licence in tree["spdx"].items():
        for dirpath, _, filenames in os.walk(stage_dir):
            for fn in filenames:
                if not fn.endswith(suffix):
                    continue
                path = os.path.join(dirpath, fn)
                text = read(path)
                if "SPDX-License-Identifier" in "".join(text.splitlines(True)[:5]):
                    continue
                write(path, f"// SPDX-License-Identifier: {licence}\n\n{text}")

    # manually-merged files stay ours; keep upstream's copy aside so `check` can
    # say how far they have drifted
    upstream_dir = os.path.join(TMP, "upstream")
    shutil.rmtree(upstream_dir, ignore_errors=True)
    for rel in tree.get("manual", []):
        staged = os.path.join(stage_dir, rel)
        if os.path.exists(staged):
            write(os.path.join(upstream_dir, rel), read(staged))
        dest = os.path.join(REPO, tree["dest"], rel)
        if os.path.exists(dest):
            write(os.path.join(stage_dir, rel), read(dest))
    return stage_dir, applied, failed


# --------------------------------------------------------------------------
# comparing / updating
# --------------------------------------------------------------------------
def tree_files(root: str) -> set[str]:
    out = set()
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in (".git", "target")]
        for fn in filenames:
            out.add(os.path.relpath(os.path.join(dirpath, fn), root))
    return out


def diff_stat(upa: str, ours: str) -> str:
    d = list(difflib.unified_diff(read(ours).splitlines(True), read(upa).splitlines(True), n=0))
    plus = sum(1 for l in d if l.startswith("+") and not l.startswith("+++"))
    minus = sum(1 for l in d if l.startswith("-") and not l.startswith("---"))
    if plus == minus == 0:
        return "identical to upstream"
    return f"+{plus}/-{minus} lines vs upstream"


def check(name: str, tree: dict) -> bool:
    stage_dir, applied, failed = stage(name, tree)
    ours = os.path.join(REPO, tree["dest"])
    a, b = tree_files(stage_dir), tree_files(ours)
    manual, keep = set(tree.get("manual", [])), set(tree.get("keep", []))
    differing, only_up = [], sorted(a - b)
    only_ours = sorted(b - a - manual - keep)

    for rel in sorted(a & b):
        if read(os.path.join(stage_dir, rel)) != read(os.path.join(ours, rel)):
            differing.append(rel)

    print(f"\n=== {name}  ({tree['dest']})")
    print(f"    upstream: {_describe(tree)}")
    print(f"    fetched:  {resolved_ref(name) or 'n/a'}")
    for note in applied:
        print(f"    re-applied: {note}")
    for note in failed:
        print(f"    !! patch no longer applies — merge by hand: {note}")
    drifting = 0
    for rel in sorted(manual):
        up = os.path.join(TMP, "upstream", rel)
        if not os.path.exists(up):
            continue
        stat = diff_stat(up, os.path.join(ours, rel))
        drifting += stat != "identical to upstream"
        print(f"    hand-merged, kept as ours: {rel}  ({stat})")
    for rel in only_ours:
        print(f"    stale (in repo, not upstream): {rel}")
    for rel in only_up:
        print(f"    available upstream, not vendored: {rel}")
    for rel in differing:
        print(f"    differs: {rel}")
        d = difflib.unified_diff(
            read(os.path.join(ours, rel)).splitlines(True),
            read(os.path.join(stage_dir, rel)).splitlines(True),
            "repo", "upstream+edits", n=1)
        sys.stdout.write("".join(list(d)[:30]))

    ok = not (failed or differing or only_ours)
    tail = f" ({drifting} hand-merged file(s) — see above)" if drifting else ""
    print(f"    -> {'in sync' + tail if ok else 'DIFFERS (see above)'}")
    return ok


def _describe(tree: dict) -> str:
    o = tree["origin"]
    if o["kind"] == "git":
        return f"{o['url']} @ {o['ref']}"
    return f"{o['name']} {o['version']} (crates.io via USTC mirror)"


def update(name: str, tree: dict) -> None:
    if subprocess.run(["git", "-C", REPO, "status", "--porcelain"],
                      capture_output=True, text=True).stdout.strip():
        sys.exit("working tree is dirty — commit or stash first")
    stage_dir, applied, failed = stage(name, tree)
    ours = os.path.join(REPO, tree["dest"])
    keep = set(tree.get("keep", []))
    staged = tree_files(stage_dir)
    for rel in tree_files(ours) - staged - keep:
        os.remove(os.path.join(ours, rel))
    for rel in staged:
        write(os.path.join(ours, rel), read(os.path.join(stage_dir, rel)))
    print(f"{name}: rewrote {tree['dest']} from {_describe(tree)} ({resolved_ref(name) or ''})")
    for note in applied:
        print(f"  re-applied: {note}")
    for note in failed:
        print(f"  !! patch not applied, merge by hand: {note}")
    print("  review with `git diff`, then fix up any hand-merged file upstream changed")


# --------------------------------------------------------------------------
def main() -> int:
    global FRESH
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("action", choices=["list", "check", "update"])
    ap.add_argument("trees", nargs="*", help="subset of trees (default: all)")
    ap.add_argument("--refresh", action="store_true", help="ignore the fetch cache")
    args = ap.parse_args()
    FRESH = args.refresh

    names = args.trees or list(MANIFEST)
    for n in names:
        if n not in MANIFEST:
            sys.exit(f"unknown tree {n!r}; known: {', '.join(MANIFEST)}")

    if args.action == "list":
        for n in names:
            t = MANIFEST[n]
            print(f"{n:18} {t['dest']}")
            print(f"{'':18} {_describe(t)}")
            print(f"{'':18} {len(t['edits'])} patch(es), "
                  f"{len(t.get('manual', []))} hand-merged, {len(t.get('keep', []))} own file(s)")
        return 0

    ok = True
    for n in names:
        if args.action == "check":
            ok &= check(n, MANIFEST[n])
        else:
            update(n, MANIFEST[n])
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
