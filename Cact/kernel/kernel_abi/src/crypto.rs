// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 CactOS Project

//! The crypto crate's exported C ABI: every `#[no_mangle]` entry point C calls
//! into `cact_crypto` (`devfs_crypto.c`, `devfs_devices.c`, `mod_tag.c`).  Each
//! is a thin thunk onto a safe `pub fn` of the same name; the raw-pointer
//! contract is the C caller's, as documented there.

use core::ffi::{c_char, c_int};

// ---- /dev/crypto: hashes, HMAC, HKDF, AEAD, key exchange --------------------
#[no_mangle]
pub unsafe extern "C" fn cact_crypt_hash(
    alg: u32,
    data: *const u8,
    data_len: u32,
    digest: *mut u8,
) -> c_int {
    cact_crypto::crypt::cact_crypt_hash(alg, data, data_len, digest)
}

#[no_mangle]
pub unsafe extern "C" fn cact_crypt_hmac_sign(
    alg: u32,
    key: *const u8,
    key_len: u32,
    data: *const u8,
    data_len: u32,
    tag: *mut u8,
) -> c_int {
    cact_crypto::crypt::cact_crypt_hmac_sign(alg, key, key_len, data, data_len, tag)
}

#[no_mangle]
pub unsafe extern "C" fn cact_crypt_hmac_verify(
    alg: u32,
    key: *const u8,
    key_len: u32,
    data: *const u8,
    data_len: u32,
    tag: *const u8,
) -> c_int {
    cact_crypto::crypt::cact_crypt_hmac_verify(alg, key, key_len, data, data_len, tag)
}

#[no_mangle]
pub unsafe extern "C" fn cact_crypt_hkdf(
    alg: u32,
    salt: *const u8,
    salt_len: u32,
    ikm: *const u8,
    ikm_len: u32,
    info: *const u8,
    info_len: u32,
    out: *mut u8,
    out_len: u32,
) -> c_int {
    cact_crypto::crypt::cact_crypt_hkdf(
        alg, salt, salt_len, ikm, ikm_len, info, info_len, out, out_len,
    )
}

#[no_mangle]
pub unsafe extern "C" fn cact_crypt_aead(
    alg: u32,
    op: u32,
    key: *const u8,
    key_len: u32,
    nonce: *const u8,
    aad: *const u8,
    aad_len: u32,
    in_len: u32,
    buf: *mut u8,
    cap: u32,
    out_len: *mut u32,
) -> c_int {
    cact_crypto::crypt::cact_crypt_aead(
        alg, op, key, key_len, nonce, aad, aad_len, in_len, buf, cap, out_len,
    )
}

#[no_mangle]
pub unsafe extern "C" fn cact_crypt_x25519_keygen(
    seed: *const u8,
    seed_len: u32,
    pub_out: *mut u8,
    priv_out: *mut u8,
) -> c_int {
    cact_crypto::crypt::cact_crypt_x25519_keygen(seed, seed_len, pub_out, priv_out)
}

#[no_mangle]
pub unsafe extern "C" fn cact_crypt_x25519_derive(
    priv_in: *const u8,
    peer_pub: *const u8,
    shared_out: *mut u8,
) -> c_int {
    cact_crypto::crypt::cact_crypt_x25519_derive(priv_in, peer_pub, shared_out)
}

#[no_mangle]
pub unsafe extern "C" fn cact_crypt_p256_keygen(
    seed: *const u8,
    seed_len: u32,
    pub_out: *mut u8,
    priv_out: *mut u8,
) -> c_int {
    cact_crypto::crypt::cact_crypt_p256_keygen(seed, seed_len, pub_out, priv_out)
}

#[no_mangle]
pub unsafe extern "C" fn cact_crypt_p256_derive(
    priv_in: *const u8,
    peer_pub: *const u8,
    shared_out: *mut u8,
) -> c_int {
    cact_crypto::crypt::cact_crypt_p256_derive(priv_in, peer_pub, shared_out)
}

#[no_mangle]
pub unsafe extern "C" fn cact_debug_xor(data: *const u8, data_len: u32) -> u32 {
    cact_crypto::crypt::cact_debug_xor(data, data_len)
}

// ---- CSPRNG ----------------------------------------------------------------
#[no_mangle]
pub unsafe extern "C" fn cact_csprng_fill(buf: *mut u8, len: u32) -> c_int {
    cact_crypto::rng::cact_csprng_fill(buf, len)
}

#[no_mangle]
pub extern "C" fn cact_csprng_hw_entropy() -> c_int {
    cact_crypto::rng::cact_csprng_hw_entropy()
}

// ---- signature verification / X.509 chain ----------------------------------
#[no_mangle]
pub unsafe extern "C" fn cact_sig_verify(
    scheme: u32,
    pubkey: *const u8,
    pubkey_len: u32,
    msg: *const u8,
    msg_len: u32,
    sig: *const u8,
    sig_len: u32,
) -> c_int {
    cact_crypto::sig::cact_sig_verify(scheme, pubkey, pubkey_len, msg, msg_len, sig, sig_len)
}

#[no_mangle]
pub unsafe extern "C" fn cact_sig_verify_p256_raw(
    pubkey: *const u8,
    pubkey_len: u32,
    msg: *const u8,
    msg_len: u32,
    sig: *const u8,
    sig_len: u32,
) -> c_int {
    cact_crypto::sig::cact_sig_verify_p256_raw(pubkey, pubkey_len, msg, msg_len, sig, sig_len)
}

#[no_mangle]
pub unsafe extern "C" fn cact_x509_verify(
    chain: *const u8,
    chain_len: u32,
    roots: *const u8,
    roots_len: u32,
    hostname: *const c_char,
    unix_time: u64,
    tls_scheme: u32,
    hs_msg: *const u8,
    hs_msg_len: u32,
    hs_sig: *const u8,
    hs_sig_len: u32,
) -> c_int {
    cact_crypto::x509::cact_x509_verify(
        chain, chain_len, roots, roots_len, hostname, unix_time, tls_scheme, hs_msg, hs_msg_len,
        hs_sig, hs_sig_len,
    )
}
