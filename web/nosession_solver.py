#!/usr/bin/env python3
"""
NO SESSION (FlagYard) - covert channel solver.

A dual-homed appliance relays a custom UDP protocol (magic "6db1"). The
payload never appears in any packet body: it is encoded in the *number of
packets per burst*. This script recovers it.

Pipeline
--------
  1. keep only data packets of one channel (default subtype 0x40)
  2. group consecutive frame numbers into bursts
  3. burst size {1,2} -> bit 0,  {4,5} -> bit 1      (684 bits = 3 x 228)
  4. drop the PN9 whitening mask  m[i] = m[i-5] ^ m[i-9], seed 101111101
  5. the first 32 dewhitened bits are a zero preamble -> 196 bits left
  6. 196 bits = 7 rows x 28 columns, read columnwise -> 28 Hamming(7,4)
     codewords -> 28 nibbles -> 14 bytes per frame
  7. each 14 bytes = 8-byte header + 4-byte payload + 2-byte CRC-16/CCITT-FALSE
  8. concatenate the three 4-byte payloads -> 12 bytes -> FlagY{...}

Usage
-----
    python3 nosession_solver.py inside_ch.csv
    python3 nosession_solver.py inside-management.pcapng --type 40
    python3 nosession_solver.py outside_ch.csv --type 20     # decoy, no signal

CSV columns (no header row):
    frame, epoch, rel_time, src, dst, sport, dport, ip_id, length, _, payload_hex

Only the standard library is needed for CSV input; scapy is required for pcap.
"""
import argparse
import csv
import re
import sys

MAGIC = "6db1"
FLAG_RE = re.compile(r"FlagY\{[^}]*\}")


# ------------------------------------------------------------------ capture
def packets_from_csv(path, subtype):
    """Return sorted (frame, time) for data packets of `subtype` (e.g. '40')."""
    want = (MAGIC + subtype).lower()
    out = []
    with open(path, newline="") as fh:
        for row in csv.reader(fh):
            if len(row) < 11:
                continue
            if row[10].strip().lower().startswith(want):
                out.append((int(row[0]), float(row[2])))
    out.sort()
    return out


def packets_from_pcap(path, subtype):
    try:
        from scapy.all import rdpcap, UDP
    except ImportError:
        sys.exit("[-] pcap input needs scapy:  pip install scapy")
    want = bytes.fromhex(MAGIC + subtype)
    out = []
    for i, pkt in enumerate(rdpcap(path), 1):
        if UDP not in pkt:
            continue
        if bytes(pkt[UDP].payload)[:3] == want:
            out.append((i, float(pkt.time)))
    out.sort()
    return out


def group_bursts(items):
    """A burst is a maximal run of packets with consecutive frame numbers."""
    if not items:
        return []
    bursts, cur = [], 1
    for prev, nxt in zip(items, items[1:]):
        if nxt[0] == prev[0] + 1:
            cur += 1
        else:
            bursts.append(cur)
            cur = 1
    bursts.append(cur)
    return bursts


# ------------------------------------------------------------------ crypto-ish
def pn9_mask(length, seed="101111101"):
    """PN9 LFSR: m[i] = m[i-5] ^ m[i-9]."""
    m = [int(b) for b in seed]
    while len(m) < length:
        m.append(m[-5] ^ m[-9])
    return m


def hamming74(codeword):
    """7 bits = p1 p2 d1 p4 d2 d3 d4. Single-bit correction.

    Returns (nibble, syndrome). syndrome == 0 means no error detected.
    """
    b = list(codeword)
    s1 = b[0] ^ b[2] ^ b[4] ^ b[6]
    s2 = b[1] ^ b[2] ^ b[5] ^ b[6]
    s4 = b[3] ^ b[4] ^ b[5] ^ b[6]
    syn = s1 | (s2 << 1) | (s4 << 2)
    if syn:
        b[syn - 1] ^= 1
    return (b[2] << 3) | (b[4] << 2) | (b[5] << 1) | b[6], syn


def crc16_ccitt_false(data):
    """CRC-16/CCITT-FALSE: poly 0x1021, init 0xFFFF, no reflection."""
    crc = 0xFFFF
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc


# ------------------------------------------------------------------ decode
def decode_frame(chunk, mask):
    """228 bits -> (14 bytes, syndromes, preamble_ok)."""
    dewhitened = [b ^ m for b, m in zip(chunk, mask)]
    preamble_ok = not any(dewhitened[:32])
    body = dewhitened[32:]                       # 196 bits

    rows = [[body[28 * r + c] for c in range(28)] for r in range(7)]
    nibbles, syndromes = [], []
    for c in range(28):
        nib, syn = hamming74([rows[r][c] for r in range(7)])
        nibbles.append(nib)
        syndromes.append(syn)

    out = bytearray()
    for i in range(0, 28, 2):
        out.append((nibbles[i] << 4) | nibbles[i + 1])
    return bytes(out), syndromes, preamble_ok


def split_record(record):
    """14 bytes -> (header, payload, crc_bytes, crc_ok)."""
    header = record[:8]
    payload = record[8:12]
    crc = record[12:14]
    want = int.from_bytes(crc, "big")
    got = crc16_ccitt_false(record[:12])
    return header, payload, crc, want == got


# ------------------------------------------------------------------ main
def main():
    ap = argparse.ArgumentParser(description="NO SESSION covert channel solver")
    ap.add_argument("capture", help="CSV export or .pcap/.pcapng file")
    ap.add_argument("--type", default="40",
                    help="data subtype in hex: 40 = inside channel, 20 = outside (default 40)")
    ap.add_argument("--quiet", action="store_true", help="only print the flag")
    args = ap.parse_args()

    subtype = args.type.lower().replace("0x", "")
    if args.capture.endswith((".pcap", ".pcapng")):
        items = packets_from_pcap(args.capture, subtype)
    else:
        items = packets_from_csv(args.capture, subtype)

    if not items:
        sys.exit(f"[-] no 0x{subtype} packets found in {args.capture}")

    bursts = group_bursts(items)
    dist = {s: bursts.count(s) for s in sorted(set(bursts))}
    if not args.quiet:
        print(f"[*] data packets : {len(items)}")
        print(f"[*] bursts       : {len(bursts)}   sizes={dist}")

    if len(bursts) % 228:
        print(f"[!] {len(bursts)} bits is not a multiple of 228 - channel may be decoy")

    bits = [0 if s in (1, 2) else 1 for s in bursts]
    if not args.quiet:
        print(f"[*] bitstream    : {len(bits)} bits "
              f"({len(bits) / 228:.2f} frames of 228)")

    mask = pn9_mask(228)
    prefix = 0
    for b in mask[:32]:
        prefix = (prefix << 1) | b
    if not args.quiet:
        print(f"[*] PN9 prefix   : {prefix:08x}  (expected beaa052b)")

    records, total_errors = [], 0
    for i in range(len(bits) // 228):
        record, syndromes, preamble_ok = decode_frame(bits[228 * i:228 * (i + 1)], mask)
        errors = sum(1 for s in syndromes if s)
        total_errors += errors
        records.append(record)
        if not args.quiet:
            print(f"[*] frame {i}      : {record.hex()}  "
                  f"corrected={errors}  preamble_zero={preamble_ok}")

    if not args.quiet:
        print(f"[*] Hamming      : {total_errors} bit error(s) corrected")

    payload = bytearray()
    all_crc_ok = True
    for i, record in enumerate(records):
        header, data, crc, crc_ok = split_record(record)
        all_crc_ok = all_crc_ok and crc_ok
        if not args.quiet:
            print(f"[*] record {i}     : header={header.hex()} data={data.hex()} "
                  f"crc={crc.hex()} {'OK' if crc_ok else 'BAD'}")
        payload += data

    if not all_crc_ok:
        print(f"[-] CRC mismatch on every record: no valid framing.")
        print(f"    This channel carries no signal (likely the decoy).")
        return 1

    flag = f"FlagY{{{payload.hex()}}}"
    if args.quiet:
        print(flag)
    else:
        print()
        print(f"    payload : {payload.hex()}")
        match = FLAG_RE.search(flag)
        print(f"    FLAG    : {match.group(0) if match else flag}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
