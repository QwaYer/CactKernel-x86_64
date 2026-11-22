// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 CactOS Project

//! 802.11 frame construction and parsing for the station engine.
//!
//! Only what a 2.4 GHz legacy STA needs (no HT/VHT): probe request, open-system
//! auth, association request, ToDS data with LLC/SNAP, and the parsers for
//! beacons / probe responses / auth / assoc responses and received data.

pub const DOT11_HDR: usize = 24;
/// The QoS control field (2 bytes), appended after A4 on a 4-address frame.
pub const QOS_CTL_LEN: usize = 2;
/// The A4 field of a WDS (repeater) frame — present only when ToDS and FromDS
/// are both set — grows the header by 6 bytes.  A4 sits right after the
/// sequence control (offset 24); QoS control then follows it (offset 30).
pub const WDS_A4_LEN: usize = 6;
pub const LLC_SNAP_LEN: usize = 8;

/// True for a WDS / repeater link frame (both ToDS and FromDS set), the 4-address
/// form whose A3 is the destination and A4 the original source
/// (IEEE 802.11-2016 9.3.2.1.3).
pub fn is_4addr(f: &[u8]) -> bool {
    f.len() >= 2 && f[1] & 0x03 == 0x03
}

/// True for a QoS data frame (a data frame, subtype bit 3).
pub fn is_qos(f: &[u8]) -> bool {
    !f.is_empty() && (f[0] >> 2) & 0x3 == 2 && ((f[0] >> 4) & 0x0f) & 0x8 != 0
}

/// Data / management header length: 24 bytes, +6 for the A4 field (WDS) and +2
/// for the QoS control.  A4 precedes the QoS control, so a 4-address QoS header
/// is 32 bytes (`ieee80211_hdrlen`).
pub fn hdr_len(f: &[u8]) -> usize {
    DOT11_HDR
        + if is_4addr(f) { WDS_A4_LEN } else { 0 }
        + if is_qos(f) { QOS_CTL_LEN } else { 0 }
}

/// Rate bitmap bit for an 802.11 supported-rate byte (low 7 bits are 0.5 Mbit/s
/// units): 0..3 are CCK 1/2/5.5/11, then 4..11 the OFDM rates 6..54.
pub fn rate_bit(half_mbit: u8) -> Option<u8> {
    match half_mbit {
        2 => Some(0),
        4 => Some(1),
        11 => Some(2),
        22 => Some(3),
        12 => Some(4),
        18 => Some(5),
        24 => Some(6),
        36 => Some(7),
        48 => Some(8),
        72 => Some(9),
        96 => Some(10),
        108 => Some(11),
        _ => None,
    }
}

/// A discovered BSS / AP, as parsed from a beacon or probe response.
#[derive(Clone, Copy)]
pub struct Bss {
    pub bssid: [u8; 6],
    pub ssid: [u8; 32],
    pub ssid_len: u8,
    pub channel: u8,
    pub privacy: u8,
    pub rsn: [u8; 64],
    pub rsn_len: u8,
    pub basic_rates: u16,
    pub erp_flags: u16,
    pub supp_rates: [u8; 16],
    pub supp_rates_len: u8,
}

impl Bss {
    pub const fn empty() -> Self {
        Bss {
            bssid: [0; 6],
            ssid: [0; 32],
            ssid_len: 0,
            channel: 0,
            privacy: 0,
            rsn: [0; 64],
            rsn_len: 0,
            basic_rates: 0,
            erp_flags: 0,
            supp_rates: [0; 16],
            supp_rates_len: 0,
        }
    }
}

pub fn frame_type_sub(f: &[u8]) -> (u8, u8) {
    if f.len() < 2 {
        return (0xff, 0xff);
    }
    ((f[0] >> 2) & 0x3, (f[0] >> 4) & 0xf)
}

/// Parse a beacon / probe response into a [`Bss`], updating `bssid`/`channel`.
pub fn parse_beacon(f: &[u8], channel_hint: u8) -> Option<Bss> {
    if f.len() < DOT11_HDR + 12 {
        return None;
    }
    let mut b = Bss::empty();
    b.bssid.copy_from_slice(&f[16..22]);
    b.privacy = if f[34] & 0x10 != 0 { 1 } else { 0 };
    b.channel = channel_hint;

    let mut ssid: Option<(usize, usize)> = None;
    let mut rsn: Option<(usize, usize)> = None;
    let mut off = DOT11_HDR + 12;
    while off + 2 <= f.len() {
        let id = f[off];
        let ilen = f[off + 1] as usize;
        if off + 2 + ilen > f.len() {
            break;
        }
        let body = &f[off + 2..off + 2 + ilen];
        match id {
            0 => ssid = Some((off + 2, ilen)),
            1 => {
                for (k, &byte) in body.iter().enumerate() {
                    if let Some(bit) = rate_bit(byte & 0x7f) {
                        if byte & 0x80 != 0 {
                            b.basic_rates |= 1u16 << bit;
                        }
                    }
                    if (b.supp_rates_len as usize) < b.supp_rates.len() && off + 2 + k < f.len() {
                        b.supp_rates[b.supp_rates_len as usize] = byte;
                        b.supp_rates_len += 1;
                    }
                }
            }
            3 => {
                if ilen >= 1 {
                    b.channel = body[0];
                }
            }
            42 => {
                if ilen >= 1 {
                    let e = body[0];
                    if e & 0x02 != 0 {
                        b.erp_flags |= 0x0002; // CTS protection
                    }
                    if e & 0x04 != 0 {
                        b.erp_flags |= 0x0001; // short preamble
                    }
                    if e & 0x08 != 0 {
                        b.erp_flags |= 0x0004; // short slot
                    }
                }
            }
            50 => {
                for &byte in body {
                    if (b.supp_rates_len as usize) < b.supp_rates.len() {
                        b.supp_rates[b.supp_rates_len as usize] = byte;
                        b.supp_rates_len += 1;
                    }
                }
            }
            48 => rsn = Some((off + 2, ilen)),
            _ => {}
        }
        off += 2 + ilen;
    }

    let (soff, slen) = ssid?;
    let slen = core::cmp::min(slen, 32);
    b.ssid[..slen].copy_from_slice(&f[soff..soff + slen]);
    b.ssid_len = slen as u8;
    if let Some((roff, rlen)) = rsn {
        let rlen = core::cmp::min(rlen, 64);
        b.rsn[..rlen].copy_from_slice(&f[roff..roff + rlen]);
        b.rsn_len = rlen as u8;
    }
    Some(b)
}

pub fn build_probe_request(our_mac: &[u8; 6]) -> [u8; 32] {
    let mut f = [0u8; 32];
    f[0] = 0x40; // probe request
    f[4..10].copy_from_slice(&[0xff; 6]); // DA broadcast
    f[10..16].copy_from_slice(our_mac);
    f[16..22].copy_from_slice(&[0xff; 6]); // BSSID broadcast
    f[24] = 0; // SSID IE: wildcard
    f[25] = 0;
    f[26] = 1; // supported rates
    f[27] = 4;
    f[28..32].copy_from_slice(&[0x82, 0x84, 0x8b, 0x96]);
    f
}

pub fn build_auth(our_mac: &[u8; 6], bssid: &[u8; 6]) -> [u8; 30] {
    let mut f = [0u8; 30];
    f[0] = 0xb0; // auth
    f[4..10].copy_from_slice(bssid);
    f[10..16].copy_from_slice(our_mac);
    f[16..22].copy_from_slice(bssid);
    f[24] = 0; // algorithm: open
    f[26] = 1; // transaction sequence 1
    f
}

/// Association request, echoing the AP's own supported rates and (for a WPA2
/// BSS) its RSN IE — hostapd rejects a station that omits either.
pub fn build_assoc(our_mac: &[u8; 6], bss: &Bss, out: &mut [u8]) -> Option<usize> {
    let mut capab: u16 = 0x0001; // ESS
    if bss.privacy != 0 {
        capab |= 0x0010;
    }
    out[0] = 0x00; // assoc request
    out[4..10].copy_from_slice(&bss.bssid);
    out[10..16].copy_from_slice(our_mac);
    out[16..22].copy_from_slice(&bss.bssid);
    let mut n = 24usize;
    out[n] = capab as u8;
    out[n + 1] = (capab >> 8) as u8;
    n += 2;
    out[n] = 10; // listen interval
    out[n + 1] = 0;
    n += 2;
    out[n] = 0; // SSID IE
    out[n + 1] = bss.ssid_len;
    n += 2;
    out[n..n + bss.ssid_len as usize].copy_from_slice(&bss.ssid[..bss.ssid_len as usize]);
    n += bss.ssid_len as usize;

    let fallback = [0x82u8, 0x84, 0x8b, 0x96];
    let (rates, rates_len): (&[u8], usize) = if bss.supp_rates_len != 0 {
        (&bss.supp_rates, bss.supp_rates_len as usize)
    } else {
        (&fallback, fallback.len())
    };
    let first = core::cmp::min(rates_len, 8);
    out[n] = 1; // supported rates
    out[n + 1] = first as u8;
    n += 2;
    out[n..n + first].copy_from_slice(&rates[..first]);
    n += first;
    if rates_len > first {
        out[n] = 50; // extended supported rates
        out[n + 1] = (rates_len - first) as u8;
        n += 2;
        out[n..n + (rates_len - first)].copy_from_slice(&rates[first..rates_len]);
        n += rates_len - first;
    }
    if bss.privacy != 0 && bss.rsn_len != 0 {
        out[n] = 48; // RSN IE
        out[n + 1] = bss.rsn_len;
        n += 2;
        out[n..n + bss.rsn_len as usize].copy_from_slice(&bss.rsn[..bss.rsn_len as usize]);
        n += bss.rsn_len as usize;
    }
    Some(n)
}

/// Wrap a payload in a ToDS data frame + LLC/SNAP with `ethertype`.
pub fn build_data_tods(
    our_mac: &[u8; 6],
    bssid: &[u8; 6],
    dst: &[u8; 6],
    ethertype: u16,
    payload: &[u8],
    out: &mut [u8],
) -> Option<usize> {
    let n_total = DOT11_HDR + LLC_SNAP_LEN + payload.len();
    if out.len() < n_total {
        return None;
    }
    out[0] = 0x08; // data
    out[1] = 0x01; // ToDS
    out[4..10].copy_from_slice(bssid); // Addr1
    out[10..16].copy_from_slice(our_mac); // Addr2
    out[16..22].copy_from_slice(dst); // Addr3
    out[22] = 0;
    out[23] = 0;
    let mut n = DOT11_HDR;
    out[n..n + 3].copy_from_slice(&[0xaa, 0xaa, 0x03]);
    out[n + 6] = (ethertype >> 8) as u8;
    out[n + 7] = ethertype as u8;
    n += LLC_SNAP_LEN;
    out[n..n + payload.len()].copy_from_slice(payload);
    Some(n + payload.len())
}

/// Wrap a payload in a WDS (ToDS+FromDS, 4-address) data frame + LLC/SNAP with
/// `ethertype`.  A1 = the AP (RA), A2 = this station (TA), A3 = `dst`, A4 =
/// `src`.  This is the form a repeater link carries bridged traffic in: `src`
/// need not be our own address, which is the whole point of A4.
pub fn build_data_wds(
    our_mac: &[u8; 6],
    bssid: &[u8; 6],
    dst: &[u8; 6],
    src: &[u8; 6],
    ethertype: u16,
    payload: &[u8],
    out: &mut [u8],
) -> Option<usize> {
    let hdr = DOT11_HDR + WDS_A4_LEN;
    let n_total = hdr + LLC_SNAP_LEN + payload.len();
    if out.len() < n_total {
        return None;
    }
    out[0] = 0x08; // data
    out[1] = 0x03; // ToDS + FromDS
    out[4..10].copy_from_slice(bssid); // A1 = RA (the AP)
    out[10..16].copy_from_slice(our_mac); // A2 = TA (this station)
    out[16..22].copy_from_slice(dst); // A3 = DA
    out[22] = 0;
    out[23] = 0;
    out[24..30].copy_from_slice(src); // A4 = SA
    let mut n = hdr;
    out[n..n + 3].copy_from_slice(&[0xaa, 0xaa, 0x03]);
    out[n + 6] = (ethertype >> 8) as u8;
    out[n + 7] = ethertype as u8;
    n += LLC_SNAP_LEN;
    out[n..n + payload.len()].copy_from_slice(payload);
    Some(n + payload.len())
}

/// True when a FromDS (3- or 4-address) data frame carries EAPOL
/// (LLC/SNAP ethertype 0x888e).
pub fn is_eapol_rx(f: &[u8]) -> bool {
    if f.len() < DOT11_HDR + LLC_SNAP_LEN {
        return false;
    }
    if frame_type_sub(f).0 != 2 || f[1] & 0x02 == 0 {
        return false;
    }
    let hdr = hdr_len(f);
    if f.len() < hdr + LLC_SNAP_LEN {
        return false;
    }
    let llc = &f[hdr..];
    llc[0] == 0xaa && llc[1] == 0xaa && llc[2] == 0x03 && llc[6] == 0x88 && llc[7] == 0x8e
}

/// Data frame header length (24, +6 for the A4 field, +2 when QoS).
pub fn data_hdr_len(f: &[u8]) -> usize {
    hdr_len(f)
}
