# NO SESSION — covert channel hidden in packet counts

![challenge](https://img.shields.io/badge/FlagYard-network%20forensics-blue)
![python](https://img.shields.io/badge/python-3.8%2B-informational)
![deps](https://img.shields.io/badge/dependencies-stdlib%20only-success)
![flag](https://img.shields.io/badge/flag-FlagY%7Ba2ba25047e8dd4a2118a813c%7D-brightgreen)

> A dual-homed appliance bridges an "inside" and an "outside" network using a
> custom UDP protocol. Nothing in the packet bodies is the message — the message
> is **how many packets** the appliance emits per burst.

**Flag**

```
FlagY{a2ba25047e8dd4a2118a813c}
```

This writeup documents only the path that worked, in the order it was found.

---

## Contents

- [1. What we were given](#1-what-we-were-given)
- [2. Two channels, one capture](#2-two-channels-one-capture)
- [3. The payload is not the message](#3-the-payload-is-not-the-message)
- [4. The signal is the packet count per burst](#4-the-signal-is-the-packet-count-per-burst)
- [5. The symbol clock is exactly 150 ms](#5-the-symbol-clock-is-exactly-150-ms)
- [6. De-whitening with PN9](#6-de-whitening-with-pn9)
- [7. Hamming(7,4), read column-wise](#7-hamming74-read-column-wise)
- [8. Framing and CRC-16](#8-framing-and-crc-16)
- [9. Assembling the flag](#9-assembling-the-flag)
- [10. Why the other channel is a decoy](#10-why-the-other-channel-is-a-decoy)
- [11. Reproduce it](#11-reproduce-it)
- [12. Repository layout](#12-repository-layout)
- [13. Defender notes](#13-defender-notes)

---

## 1. What we were given

A capture from a host that sits between two networks:

| Property | Value |
| --- | --- |
| Flow | `10.90.4.23:57150` ↔ `10.90.4.1:48620` |
| Transport | UDP |
| Application magic | `6db1` (first two bytes of every payload) |
| Tag | `44414a58` — ASCII `DAJX` on every packet |

Every packet starts with `6db1`, then a one-byte **subtype**, then the 4-byte tag.
That subtype byte is the only thing that distinguishes the message packets from
their acknowledgements and from the second, unrelated channel.

The payload lengths are small and regular: `7` bytes for the session open,
`13` bytes for data and acks, `19` bytes for the session-open reply.

```
6db1 30 44414a58                                    <- open    (1 packet)
6db1 40 44414a58 <4B nonce> <2B field>              <- data    (2192 packets)
6db1 c0 44414a58 <4B nonce> <2B field>              <- ack     (2192 packets)
6db1 b0 44414a58 00065bff50cd0e32000249f0           <- open-reply (12B token)
```

## 2. Two channels, one capture

Splitting the capture by the subtype byte immediately shows two independent
conversations, each with its own open / data / ack / open-reply quartet:

| Subtype | Role | Packets |
| --- | --- | --- |
| `0x30` / `0xb0` | open / open-reply, **inside** | 1 / 1 |
| `0x40` / `0xc0` | data / ack, **inside** | **2192** / 2192 |
| `0x10` / `0x90` | open / open-reply, **outside** | 1 / 1 |
| `0x20` / `0xa0` | data / ack, **outside** | **685** / 685 |

Total: 4,386 packets inside, 1,372 outside. Both channels use the same magic,
the same tag and the same 150 ms cadence, so the second one cannot be dismissed
without decoding it — that is where the decoy lives (see §10).

## 3. The payload is not the message

The obvious move is to read the 13-byte data payloads: `4` bytes of nonce plus
`2` trailing bytes that look exactly like a checksum. It is a dead end:

- the 4-byte nonce is different on every packet and never repeats;
- the trailing 2 bytes **do not validate** as CRC-16/CCITT-FALSE, XMODEM, ARC,
  MODBUS, X25 or KERMIT over any prefix of the packet;
- the 12-byte token in the open-reply (`00065bff50cd0e32000249f0`) is used by
  both channels and contains no structure that decodes to anything.

The payloads are cover traffic. The appliance is only *keeping the channel busy*
while it signals somewhere else.

## 4. The signal is the packet count per burst

The data packets arrive back to back in tight groups, and the **size of each
group varies**. Counting consecutive frame numbers (`frame[i+1] == frame[i] + 1`)
into bursts gives:

| Burst size | Count |
| --- | --- |
| 1 | 152 |
| 2 | 149 |
| 3 | 0 |
| 4 | 173 |
| 5 | 210 |
| **total bursts** | **684** |

Only two *ranges* appear: `{1,2}` and `{4,5}`. The gap at `3` is the dead zone
between symbols — a natural way to build a two-level signal that survives
jitter:

```
size in {1,2}  ->  bit 0        (152 + 149 = 301 bits)
size in {4,5}  ->  bit 1        (173 + 210 = 383 bits)
```

684 bits. That is not a multiple of 8, nor of 10, but it *is* `3 × 228` — three
identical-length frames, which is the first strong hint that the bitstream is a
framed, forward-error-corrected link.

## 5. The symbol clock is exactly 150 ms

Burst start times are metronomically spaced:

| Metric | Value |
| --- | --- |
| First → last burst | 102.450 s |
| Inter-burst delta | min 149.1 ms, median **150.0 ms**, max 151.0 ms |
| Symbols | 684 (one burst = one bit) |
| Effective bit rate | ≈ 6.67 bit/s |

The stability of the clock confirms the burst/symbol mapping: there is no need
to guess bit boundaries, one burst is one bit. The inter-packet gap *inside* a
burst is essentially zero, so the only thing the receiver can measure is the
burst length itself.

## 6. De-whitening with PN9

A raw bitstream that starts with a long run of `1`s tends to be scrambled before
transmission, and here the first 32 de-whitened bits must be a zero preamble —
the standard framing trick. The mask is the classic PN9 LFSR:

```
m[i] = m[i-5] ^ m[i-9]        seed (first 9 bits): 101111101
```

XORing the 684-bit stream with this mask reproduces the train of zeros at the
start of every 228-bit frame, which is the proof that the mask (and the frame
alignment) is correct. The first 32 mask bits are:

```
beaa052b
```

Frames are then cut as `228 bits = 32-bit preamble + 196-bit body`.

## 7. Hamming(7,4), read column-wise

196 is not divisible by 7 in the expected direction, but `196 = 7 × 28`. The
body is therefore a **7-row × 28-column matrix** and the codewords run down the
*columns*, not along the rows (a deliberate transposition to break naive bit
readers):

```
row 0  c0 c1 ... c27
row 1  c0 c1 ... c27
...
row 6  c0 c1 ... c27
        |  |        |
        v  v        v
      cw0 cw1 ... cw27      each column = one Hamming(7,4) codeword
```

Bit order inside a codeword is `p1 p2 d1 p4 d2 d3 d4`. For each column the three
parity checks

```
s1 = b0^b2^b4^b6      s2 = b1^b2^b5^b6      s4 = b3^b4^b5^b6
syndrome = s1 | s2<<1 | s4<<2
```

give a non-zero syndrome in exactly one column per frame, and flipping that bit
makes the syndrome zero. **One bit corrected per frame, three frames, zero
remaining errors** — the FEC is real, and it is what makes the packet-count
channel usable at all.

28 codewords → 28 nibbles → **14 bytes per frame**.

## 8. Framing and CRC-16

Each 14-byte frame is a record:

```
 a7c3   01   00   03040817   a2ba2504   72bb
 ^^^^   ^^   ^^   ^^^^^^^^   ^^^^^^^^   ^^^^
 magic  ver  idx  session    data(4B)   CRC-16/CCITT-FALSE
```

- `8`-byte header: magic `a7c3`, version `01`, frame index (`00`,`01`,`02`),
  4-byte session id `03040817`
- `4`-byte data
- `2`-byte **CRC-16/CCITT-FALSE** (poly `0x1021`, init `0xFFFF`, no reflection)
  computed over the first **12** bytes

All three records validate:

| # | record | CRC |
| --- | --- | --- |
| 0 | `a7c3010003040817` `a2ba2504` `72bb` | OK |
| 1 | `a7c3010103040817` `7e8dd4a2` `cb40` | OK |
| 2 | `a7c3010203040817` `118a813c` `7d95` | OK |

## 9. Assembling the flag

Concatenating the three 4-byte data fields in frame order:

```
a2ba2504 | 7e8dd4a2 | 118a813c
```

```
FlagY{a2ba25047e8dd4a2118a813c}
```

## 10. Why the other channel is a decoy

The `0x20` channel is the perfect trap: same magic, same tag, same 150 ms clock,
same packet count ballpark.

| Check | `0x40` (inside) | `0x20` (outside) |
| --- | --- | --- |
| Data packets | 2192 | 685 |
| Bursts | 684 | 685 |
| Burst sizes | `{1:152, 2:149, 4:173, 5:210}` | `{1:685}` — every burst is a single packet |
| Bits | 684 = 3 × 228 | 685 (not a multiple of 228) |
| De-whitening preamble | 32 zeros | no |
| CRC-16 | 3/3 OK | **0/3 OK** |

Every burst being exactly one packet means the stream is a constant: it can only
encode zeros, it never meets the frame length, and every record it produces
fails CRC. **The CRC is the oracle** — it is what separates a real framing from
a stuffed channel, and it is why the solver refuses to print a flag from this
one.

## 11. Reproduce it

```bash
# full decode (works on the CSV export or directly on the pcap)
python3 solver/nosession_solver.py captures/inside_ch.csv
python3 solver/nosession_solver.py inside-management.pcapng --type 40

# the decoy: exits 1, prints no flag
python3 solver/nosession_solver.py captures/outside_ch.csv --type 20
```

Expected output on the inside channel:

```
[*] data packets : 2192
[*] bursts       : 684   sizes={1: 152, 2: 149, 4: 173, 5: 210}
[*] bitstream    : 684 bits (3.00 frames of 228)
[*] PN9 prefix   : beaa052b  (expected beaa052b)
[*] frame 0      : a7c3010003040817a2ba250472bb  corrected=1  preamble_zero=True
[*] frame 1      : a7c30101030408177e8dd4a2cb40  corrected=1  preamble_zero=True
[*] frame 2      : a7c3010203040817118a813c7d95  corrected=1  preamble_zero=True
[*] Hamming      : 3 bit error(s) corrected
[*] record 0     : header=a7c3010003040817 data=a2ba2504 crc=72bb OK
[*] record 1     : header=a7c3010103040817 data=7e8dd4a2 crc=cb40 OK
[*] record 2     : header=a7c3010203040817 data=118a813c crc=7d95 OK

    payload : a2ba25047e8dd4a2118a813c
    FLAG    : FlagY{a2ba25047e8dd4a2118a813c}
```

No third-party packages are needed for CSV input. `.pcap` / `.pcapng` input uses
`scapy` (`pip install scapy`).

CSV columns (no header row), as exported for this writeup:

```
frame, epoch, rel_time, src, dst, sport, dport, ip_id, length, _, payload_hex
```

## 12. Repository layout

```
NoSession/
├── README.md                     <- this file
├── README.ar.md                  <- Arabic version
├── .gitignore
├── solver/
│   └── nosession_solver.py       <- burst grouping, PN9, Hamming(7,4), CRC, flag
└── captures/
    ├── inside_ch.csv             <- 0x40 channel, 2192 data packets (carries the flag)
    └── outside_ch.csv            <- 0x20 channel, 685 data packets (decoy)
```

Minimal pipeline implemented by the solver:

```
subtype filter -> burst grouping -> {1,2}=0 {4,5}=1 -> PN9 XOR
   -> 228-bit frames -> 7x28 matrix -> Hamming(7,4) x28 -> 14-byte record
   -> CRC-16/CCITT-FALSE gate -> 3 x 4B payload -> FlagY{...}
```

## 13. Defender notes

A packet-count channel is invisible to payload inspection and to DPI signatures,
so the useful detections are statistical rather than content-based:

- **Flow-shape baselining.** For long-lived UDP flows, alert on a stable
  inter-burst period combined with a bimodal burst-size distribution. A
  low-variance `ΔT` (here σ ≈ 0.4 ms around 150 ms) over thousands of bursts has
  no legitimate explanation in most environments.
- **Symbol-rate awareness.** 6.67 bit/s is slow but continuous; the tell is the
  *regularity*, not the volume.
- **Entropy of burst sizes.** Two clusters with an empty middle is a textbook
  binary modulation. Track `H(burst_size)` per flow.
- **Constant-size cover traffic from a dual-homed host** — small, uniform,
  nonce-bearing payloads that never vary in length are a strong secondary
  indicator.
- **Cross-segment correlation.** The channel only exists because one host can
  see both segments; egress monitoring alone misses it.

Mitigation for the design class: do not let a relay decide its own pacing —
batch and pad at the gateway (constant-rate emission, fixed burst size), or
terminate the protocol at an application proxy that re-emits on its own schedule.
