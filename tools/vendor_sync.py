#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 CactOS Project

"""vendor_sync.py — refresh the vendored third-party trees from their upstreams.

The kernel vendors four third-party trees (see the UPSTREAM.md next to each).
Each one is upstream code *plus* a small, recorded set of CactOS edits, so
"sync" means: fetch the upstream ref, re-apply the recorded edits, and compare
the result with what is in the tree.  The recorded edits live in MANIFEST below;
if upstream moves a brace the edit no longer applies and the tool says so rather
than silently dropping it.

    tools/vendor_sync.py list                  # trees, upstream refs, edit counts
    tools/vendor_sync.py check [tree ...]       # fetch, re-apply, diff vs the tree
    tools/vendor_sync.py update <tree> [...]    # rewrite the tree from upstream

`check` never writes to the repository.  `update` does, so it refuses to run on a
dirty working tree and prints a summary to review before `git add`.

Network notes for this machine: crates.io/static.crates.io are blocked, so
crates come from the USTC mirror; github.com, raw.githubusercontent.com and
git.kernel.org work.  Nothing here runs during a normal build.
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

# --------------------------------------------------------------------------
# Manifest: one entry per vendored tree.
#
# dest        where the tree lives in the repo
# origin      how to fetch upstream:
#               git   -> url + ref(tag) + optional subdir of the checkout
#               crate -> name + version, from the USTC mirror
# take        if set, only these paths (relative to the fetched root) are
#             considered part of the vendored tree; everything else upstream
#             is deliberately not vendored
# drop        paths removed from the fetched tree before comparison
# spdx        {glob-suffix: licence} - one `// SPDX-License-Identifier:` line
#             is added at the top of every matching file
# overrides   files kept as CactOS's own; upstream's copy is never copied over
# edits       ordered text substitutions re-applied after each fetch; a
#             substitution that no longer matches is reported as a failure
# --------------------------------------------------------------------------
MANIFEST: dict[str, dict] = {
    "rustls": {
        "dest": "Cact/crypto/vendor/rustls-0.23.40",
        "origin": {"kind": "git", "url": "https://github.com/rustls/rustls",
                   "ref": "v/0.23.40"},
        # the repo root, minus the workspace members we do not use and the
        # test fixtures (several MB of .der/.bin)
        "take": [".cargo", ".github", ".gitignore", ".lycheeignore",
                 ".rustfmt.toml", ".rustfmt.unstable.toml", ".taplo.toml",
                 "Cargo.toml", "LICENSE", "LICENSE-APACHE", "LICENSE-ISC",
                 "LICENSE-MIT", "README.md", "rustls"],
        "drop": ["rustls/src/testdata", "rustls/tests/data"],
        "spdx": {".rs": "Apache-2.0 OR ISC OR MIT"},
        "overrides": ["rustls/Cargo.toml", "rustls/build.rs"],
        "edits": [
            {
                "file": "rustls/src/lib.rs",
                "find": "mod conn;\n",
                "replace": "/// Connection APIs: the shared connection state and the client/server halves.\npub mod conn;\n",
                "note": "cact_crypto/cact_net reach conn from outside the crate",
            },
            {
                "file": "rustls/src/conn.rs",
                "find": "pub(crate) mod unbuffered;\n",
                "replace": "pub mod unbuffered;\n",
                "note": "cact_crypto/cact_net reach unbuffered from outside the crate",
            },
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
        "overrides": ["Cargo.toml"],
        "edits": [
            {
                "file": "src/lib.rs",
                "find": '#[cfg(any(feature = "std", test))]\nextern crate std;\n\n',
                "replace": "",
                "note": "no_std: the kernel has no std to link",
            },
        ],
    },
    "rustls-pki-types": {
        "dest": "Cact/crypto/vendor/rustls-pki-types",
        "origin": {"kind": "crate", "name": "rustls-pki-types", "version": "1.12.0"},
        "take": None,
        "drop": [".gitignore", "tests"],
        "spdx": {".rs": "MIT OR Apache-2.0"},
        "overrides": [".cargo-checksum.json"],
        "edits": [],
    },
}


# --------------------------------------------------------------------------
# fetching
# --------------------------------------------------------------------------
def fetch_git(url: str, ref: str, subdir: str | None) -> str:
    out = os.path.join(TMP, "src")
    shutil.rmtree(out, ignore_errors=True)
    os.makedirs(TMP, exist_ok=True)
    run(["git", "clone", "--quiet", "--depth", "1", "--branch", ref, url, out])
    return os.path.join(out, subdir) if subdir else out


def fetch_crate(name: str, version: str) -> str:
    out = os.path.join(TMP, "src")
    shutil.rmtree(out, ignore_errors=True)
    os.makedirs(out)
    url = f"{MIRROR}/{name}/{version}/download"
    tarball = os.path.join(TMP, f"{name}-{version}.crate")
    with urllib.request.urlopen(url, timeout=120) as r, open(tarball, "wb") as f:
        shutil.copyfileobj(r, f)
    with tarfile.open(tarball, "r:gz") as t:
        t.extractall(out)
    return os.path.join(out, f"{name}-{version}")


def run(cmd: list[str], cwd: str | None = None) -> None:
    p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    if p.returncode != 0:
        sys.exit(f"failed: {' '.join(cmd)}\n{p.stderr}")


def fetch(tree: dict) -> str:
    o = tree["origin"]
    if o["kind"] == "git":
        return fetch_git(o["url"], o["ref"], o.get("subdir"))
    if o["kind"] == "crate":
        return fetch_crate(o["name"], o["version"])
    raise SystemExit(f"unknown origin kind {o['kind']!r}")


# --------------------------------------------------------------------------
# staging: fetched upstream -> "what the vendored tree should look like"
# --------------------------------------------------------------------------
def read(path: str) -> str:
    with open(path, "rb") as f:
        return f.read().decode("utf-8", "surrogateescape")


def write(path: str, text: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(text.encode("utf-8", "surrogateescape"))


def stage(name: str, tree: dict) -> tuple[str, list[str], list[str]]:
    src = fetch(tree)
    stage_dir = os.path.join(TMP, "stage")
    shutil.rmtree(stage_dir, ignore_errors=True)

    take = tree.get("take")
    drop = {os.path.normpath(d) for d in tree.get("drop", [])}
    for dirpath, dirnames, filenames in os.walk(src):
        rel_dir = os.path.relpath(dirpath, src)
        for fn in filenames:
            rel = fn if rel_dir == "." else os.path.join(rel_dir, fn)
            if take and not any(rel == t or rel.startswith(t + os.sep) for t in take):
                continue
            if any(rel == d or rel.startswith(d + os.sep) for d in drop):
                continue
            write(os.path.join(stage_dir, rel), read(os.path.join(dirpath, fn)))

    applied, failed = [], []
    for e in tree["edits"]:
        path = os.path.join(stage_dir, e["file"])
        text = read(path)
        if e["find"] not in text:
            failed.append(f"{e['file']}: {e['note']}")
            continue
        write(path, text.replace(e["find"], e["replace"], 1))
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

    # Overrides stay ours; keep upstream's copy aside so `check` can say how far
    # they have drifted (an upstream Cargo.toml that grew a feature we lack is
    # exactly what a maintainer needs to see on a version bump).
    upstream_dir = os.path.join(TMP, "upstream")
    shutil.rmtree(upstream_dir, ignore_errors=True)
    for rel in tree["overrides"]:
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


def check(name: str, tree: dict) -> bool:
    stage_dir, applied, failed = stage(name, tree)
    ours = os.path.join(REPO, tree["dest"])
    a, b = tree_files(stage_dir), tree_files(ours)
    overrides = set(tree["overrides"])
    differing, only_up = [], sorted(a - b)
    only_ours = sorted(b - a - overrides)

    for rel in sorted(a & b):
        if read(os.path.join(stage_dir, rel)) != read(os.path.join(ours, rel)):
            differing.append(rel)

    print(f"\n=== {name}  ({tree['dest']})")
    print(f"    upstream: {_describe(tree)}")
    for note in applied:
        print(f"    re-applied: {note}")
    for note in failed:
        print(f"    !! edit no longer applies — merge by hand: {note}")
    for rel in sorted(overrides):
        up = os.path.join(TMP, "upstream", rel)
        if not os.path.exists(up):
            continue
        delta = diff_stat(up, os.path.join(ours, rel))
        print(f"    override, kept as ours: {rel}  (vs upstream: {delta} — review on a bump)")
    for rel in only_ours:
        print(f"    stale (in repo, not upstream): {rel}")
    for rel in only_up:
        print(f"    available upstream, not vendored: {rel}")
    for rel in differing:
        print(f"    differs: {rel}")
        d = difflib.unified_diff(
            read(os.path.join(ours, rel)).splitlines(True),
            read(os.path.join(stage_dir, rel)).splitlines(True),
            "repo", "upstream+edits", n=1,
        )
        sys.stdout.write("".join(list(d)[:30]))

    ok = not (failed or differing or only_ours)
    print(f"    -> {'in sync' if ok else 'DIFFERS (see above)'}")
    return ok


def diff_stat(upa: str, ours: str) -> str:
    d = list(difflib.unified_diff(read(ours).splitlines(True), read(upa).splitlines(True), n=0))
    plus = sum(1 for l in d if l.startswith("+") and not l.startswith("+++"))
    minus = sum(1 for l in d if l.startswith("-") and not l.startswith("---"))
    return "identical" if plus == minus == 0 else f"+{plus}/-{minus} lines"


def _describe(tree: dict) -> str:
    o = tree["origin"]
    if o["kind"] == "git":
        return f"{o['url']} @ {o['ref']}" + (f"/{o['subdir']}" if o.get("subdir") else "")
    return f"{o['name']} {o['version']} (crates.io via USTC mirror)"


def update(name: str, tree: dict) -> None:
    if subprocess.run(["git", "-C", REPO, "status", "--porcelain"],
                      capture_output=True, text=True).stdout.strip():
        sys.exit("working tree is dirty — commit or stash first")
    stage_dir, applied, failed = stage(name, tree)
    ours = os.path.join(REPO, tree["dest"])
    for rel in tree_files(ours):
        if rel not in tree_files(stage_dir):
            os.remove(os.path.join(ours, rel))
    for rel in tree_files(stage_dir):
        write(os.path.join(ours, rel), read(os.path.join(stage_dir, rel)))
    print(f"{name}: rewrote {tree['dest']} from {_describe(tree)}")
    for note in applied:
        print(f"  edit: {note}")
    for note in failed:
        print(f"  !! edit not applied, merge by hand: {note}")
    print("  review with `git diff`, then fix up any override that upstream changed")


# --------------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("action", choices=["list", "check", "update"])
    ap.add_argument("trees", nargs="*", help="subset of trees (default: all)")
    args = ap.parse_args()

    names = args.trees or list(MANIFEST)
    for n in names:
        if n not in MANIFEST:
            sys.exit(f"unknown tree {n!r}; known: {', '.join(MANIFEST)}")

    if args.action == "list":
        for n in names:
            t = MANIFEST[n]
            print(f"{n:18} {t['dest']}")
            print(f"{'':18} {_describe(t)}")
            print(f"{'':18} {len(t['edits'])} edit(s), {len(t['overrides'])} override(s)")
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
