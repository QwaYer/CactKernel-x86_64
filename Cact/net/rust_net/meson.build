# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 CactOS Project

_rust_inputs = []
# The archive also links this crate's in-repo path dependency cact_crypto, so
# its sources must be inputs too: without them ninja considers libcact_net.a up
# to date after an edit to the crypto crate.  Vendored crates under
# Cact/crypto/vendor are pruned (imported source drops, not edited here).
_crypto_src = meson.project_source_root() / 'Cact/crypto'
_found = run_command('sh', '-c',
  'find ' + meson.current_source_dir() + ' ' + _crypto_src +
  ' \\( -name target -o -name vendor \\) -prune -o -type f -print | LC_ALL=C sort',
  check: true)

foreach f : _found.stdout().strip().split('\n')
  if f != ''
    _rust_inputs += f
  endif
endforeach

# `cact_net` is an rlib now; the kernel's single Rust archive is built by
# `Cact/kernel/kernel_rust` (see its src/lib.rs for why).
