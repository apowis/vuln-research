# Methodology, lessons and dead ends

Reference material for the method posts and for anyone re-running the hunts. The skills themselves
hold the authoritative recipes: `.claude/skills/hunting-protocol-memory-leaks/references/` and
`.claude/skills/hunting-weird-protocol-data/references/`.

## The two skills

### hunting-protocol-memory-leaks

- **History.**
  - Created in PR #4510 (merged 2026-10-09).
  - #4530 (2026-10-14) added structural kinds, a passive temporal check, stratified sweeps and the
    coturn source-column fix.
  - #4660 and #4665 (2026-10-21) added the raw-column catalogue and verdicts.
  - #4739 followed the NetBIOS closure.
- **Phases.** 0 scope and cost gate, then 1 catalogue, 2 sweep, 3 score, 4 confirm, 5 disclose or
  write a rule.
- **`catalog.yaml`** gives each field's grammar (NUL-terminated, length-prefixed, echo-expected,
  reserved-zero, enum, text charset) and the column that holds raw bytes.
- **Structural kinds** used for detection:
  - trailing slack after a NUL;
  - declared length against actual length;
  - echo-expected divergence;
  - reserved-zero violated;
  - enum out of range;
  - control bytes in text.
- **Scoring.**
  - **host_variance**: the value changes between observations of the same host. Live memory
    changes; constants don't.
  - **pointer_rate**: 32-bit words in plausible heap or user ranges, `ffffffff` runs, `0x7f..`
    fragments.
  - **The NUL-trimmed tail**: what is left after the terminator.
  - Entropy was demoted from the primary tell during calibration. Reused-buffer leaks run at 2.6-3.9
    bits per byte, not ~8.
- **Stratification.** Score per vendor or version stratum and rank by the best stratum with 50 or more
  hosts. PPTP is 0.02 flat and 0.58 in the Cisco stratum.
- **Regression set.** Run it first every time.
  - Known positives: PPTP Cisco (~0.58) and coturn (~0.007 flat, pointer rate 0.7).
  - Decoys: C1-C6, including SNMP sysDescr GBK charset and IPsec CSPRNG Informational cookies.
- **Cost.** Under $1 per full sweep. Run 1 cost about $0.35 + $0.75; run 2 under $0.10.

### hunting-weird-protocol-data

- **History.** Created in #4678 (2026-10-22). #4686 added 21 noise-registry rows, 7 confounder rows
  and 4 red flags.
- **Method.**
  1. Profile each protocol and message type by byte offset.
  2. Score rare values at low-entropy header offsets.
  3. Cluster by signature: message type plus the set of rare offsets plus their values.
  4. Gate on spread: ASNs, /16s, top-ASN share, days present.
  5. Enrich with IP intel, canaries and fingerprints.
  6. Promote to an IOC package or a product lead.
- **Controls.**
  - Synthetic control A must come out promoted (in the 11-12 run: 84 hosts, 12 ASNs).
  - Control B must come out a near-miss (1 ASN).
  - Controls caught two threshold errors while the skill was built: a rarity gate alone never flagged
    control A, and CAP 128 flooded the list with vendor-string offsets.
- **Noise registry** (`noise-registry.md`). Matches on protocol, message type and the exact set of
  rare offsets, not byte values, so drifting counters stay suppressed. One known flaw: on udp/5683 a
  single offset set held both an echo and a real blob, so it was left unmarked.
- **Method shifts by November.**
  - The per-protocol offset sweep mostly reproduced registry noise.
  - New signal came from **cross-port shape sweeps** (first 8 bytes by port) over UDP and over
    `unknown_staging` TCP banners (base64, about 381k hosts a day).
- **Parsed-only tables** (netbios, mdns, bgp) have no raw bytes, so they were swept with a
  parsed-shape signature.

## Verification ladder

The order that kept us honest:

1. A passive BYTES-level signal in BigQuery.
2. Rule out our own probe: echo overlap, the probe change date, a comparison with the well-formed
   probe.
3. A per-cycle temporal check from `*_staging`, since the snapshot holds one row.
4. Vendor attribution: `fingerprint_latest`, SNMP sysDescr, port profile.
5. Source reading or firmware RE where available.
6. **One active confirmation probe** from sprox-03 (or an approved VM), with a well-formed control
   and a negative control. Send only bytes the scanner already sends.
7. **An existing-CVE search**: `get_cpe_cves`, a web or advisory search, the vendor PSIRT page.
   NVD can carry no CPE configuration (ABB), and CNA-only ranges are "Deferred" (Juniper SSR).
8. Disclose, or write a detection rule, or both.

Single external probes settled two questions SQL could not: DrayTek (a passive zero is not a safe
host) and the NetBIOS echo (a fixed txid came back verbatim).

## Lessons

- **Work in BYTES.** BigQuery STRING keeps invalid UTF-8, but its regex functions fail or undercount.
  Use `CAST(x AS BYTES)`. JS UDFs must take BYTES or hex.
- **Use the right column.** The coturn reason phrase is only in `stun_staging.reason_phrase`.
  `stun_snapshot.raw_response` holds the Binding Success; a UDF walking it for attribute 0x0009 found
  0 of 23,203. The skill catalogue silently returned 0 until this was corrected.
- **A uniform 16-bit random head is request echo** (a txid), not heap memory.
- **High host_variance plus maximally diverse content with no pointer or ASCII tells is a CSPRNG**,
  not a leak. Example: IKE Informational cookies.
- **Clean negatives expire.** The 10-12 IKE result was right for the corrupted probe. The fixed probe
  exposed BENIGNCERTAIN.
- **Our probes shape what we can see,** in both directions. A malformed probe triggered DrayTek. A
  well-formed one triggered Cisco. The IPSEC_START corrupted probe stays because 24k hosts answer
  only malformed input.
- **Echo and replay are the biggest confounders.** Compare against all bytes the task wrote, not just
  this connection's. Replay hosts can hand you third-party bytes.
- **Product constants are not IOCs.** An odd constant chosen by the responder is an implementation
  fingerprint; promote it as `unknown`.
- **Don't fingerprint malware by a property of its network.** The Darklantern echo really belonged
  to two ISPs.
- **Rules beat k-means for proof.** k-means ranked mostly by length and size combinations. It found
  no implants, echoes or decoys. Use contamination 0.01, not 0.001: at 0.001 it returned about 20 HTTP
  rows, not the roughly 10k expected, and the cause is unresolved. Autoencoder and ARIMA_PLUS were
  not tested.
- **Rule baselines were the bigger win of the ML pilot.** It exposed gaps: the SNMP NX-OS tell, where
  the rule caught 112 of 181; a threshold set at exactly 200; 26 Cisco 7200 replies scored highest
  only because of our own 1,024-byte storage cap.

## Capture blind spots

These limit what the passive hunts can claim.

- **UDP banner caps.** The default stored banner is 32 bytes (`udpx_scanner.go:186`). #4685 raised it
  to 64 bytes on ports 16384 and up. #4695 raised it to 1,500 bytes on ports 53, 123, 161, 500, 443,
  3478, 47808 and 44818. The old era is unrecoverable past byte 32.
- **Columns that don't hold what they seem to:**
  - `smb.ntlm` is a text version string.
  - `mysql_staging.error_code` is 0 everywhere.
  - `sip.headers`, `ldap.matched_dn`, the oracle redirect, `redis.auth_response` and `ipp.attributes`
    are empty.
  - zgrab2 socks5 stores a zero-filled 10-byte buffer.
  - `dns_staging` has no `version_bind`.
  - `ipsec_snapshot` has no raw bytes; use `ipsec_staging.raw_response`.
- **Not stored at all:** the Modbus MBAP length (product#4631), the NetBIOS txid and statistics block
  (#4752), and SSH KEXINIT (#4392). Other capture issues are #4627-#4633.
- **HTTP and TLS** are outside the passive leak hunt. This is the largest standing blind spot.
- **JA4T** keeps only option kinds, so the DrayTek kind-30 trailing byte needs raw SYN-ACKs.

## Cost notes

- A plain sweep query costs about $0.01. PPTP byte queries cost about $0.02 each.
- **IP-intel coverage** via the `ipintel` view scans 109-165 GiB (about $0.9-1.0). Joining
  `fingerprint_latest` and reading `fields.classifications` gives the same coverage for $0.03.
- **Geo.** The skill's prefix-length cross join against `ipgeo_snapshot` cost $0.42-$0.73 at a few
  thousand hosts. A /16-bucket range join (`ip_int >> 16` plus BETWEEN) cost $0.02 for 120k hosts.
- **One missing `DISTINCT`** in the coverage SQL caused a 270k fan-out and a second ipintel scan.
- `bqcost.sh --timeout=300000` trips the $5 gate; 120000 is the maximum.
- The k-means pilot cost about $0.10 for HTTP and under a cent for each other protocol.
- The echo measurement on 11-05 cost about $6. That was the most expensive single session.

## Dead ends

- **DrayTek 4.x firmware decryption.** It uses a modified ChaCha; the key was recovered, the cipher
  not cracked. It wasn't needed, and web searches about it trip the safety classifier.
- **V2865 emulation.** It is a MIPS bare-metal image with no QEMU machine, so a Unicorn harness on the
  real handler was used instead.
- **IOS version split for BENIGNCERTAIN.** There was too little version data.
- **coturn natural leak in the lab.** The container stack held zeros, so only a gdb-seeded run shows
  bytes.
- **BigQuery Graph.** Needs Enterprise; it was confused with BQML, which does not.
- **Agent mechanics.** Parallel subagents collided on a shared scratch file (`feat.sql`).
