# Findings catalogue

Each entry gives: what it is, how it was found, key numbers, verdict, outputs, sensitivities and a
blog angle. The session IDs are Claude Code transcript prefixes under
`~/.claude/projects/-Users-adampowis-vulncheck-anchorbreaker/` unless another project is named. See
`sources.md` for the full list. "(inference)" marks something reasoned rather than read in the data
or transcript.

---

## Tier 1: vulnerabilities

### 1. coturn 4.10.0 ERROR-CODE reason-phrase stack leak: CVE-2026-104074 (new)

**What it is.** In coturn 4.10.0 only, `stun_init_error_response_common_str`
(`src/client/ns_turn_msg.c`) leaves the stack buffer `avalue[513]` uninitialised.

- Commit `20d8e382` (PR #1829, 2026-03-06, first shipped in 4.10.0) made the reason string optional
  to cut amplification. It defaults to off (`--include-reason-string` false), so the default config
  is vulnerable.
- With the option off, the code skips the `strncpy` but does not zero the buffer.
  `strlen(avalue+4)` then reads leftover stack into the ERROR-CODE reason phrase.
- An unauthenticated TURN Allocate that draws a 401 is enough to trigger it. Each response leaks
  from 4 to about 508 bytes, and the bytes change on every request.
- Fixed silently in 4.11.0 when fuzzing PR #1878 (commit `741b2983`) put back
  `memset(avalue,0,...)`. There was no advisory.
- It is the same bug class as CVE-2020-4067 (a different buffer, fixed in 4.5.1.3), so in effect a
  regression.

**How it was found.**
1. 2026-10-06, session `8bef625a` (deleted). The question was "could we write a TURN scanner, and
   would it add CPE tagging?" A subagent piloted TURN Allocate (REQUESTED-TRANSPORT=UDP) against
   BigQuery-sampled IPs to attribute STUN hosts that send no SOFTWARE attribute.
2. The new `reason_phrase` field in `stun_staging` held bytes after the point where the text should
   end. Bytes outside the field's grammar are the memory-disclosure tell.
3. 2026-10-07, session `6bd4aa17` (deleted). A BigQuery sweep found 58 leaking hosts with stable
   leak shapes that correlated with coturn.
4. Reading the source plus git blame across releases gave the version boundary: 4.10.0 lacks the
   memset, 4.11.0 and master have it.
5. Valgrind Memcheck on coturn built from tag 4.10.0 in Docker, sent one unauthenticated Allocate,
   reported deterministically: "Conditional jump or move depends on uninitialised value(s) at
   strlen, by stun_init_error_response_common_str".
6. Valgrind did not flag the socket send. In the container `avalue[4]` happened to be 0, so `strlen`
   returned 0 and the reply carried an empty reason. That explains the ~450 hosts that send an empty
   reason with a 16-byte nonce: they are vulnerable, but their worker stack held zeros at that
   moment.

**Numbers.**
- 58 leaking hosts at discovery. 5 of them start with a printable byte, so the first rule's
  `^[^\x20-\x7e]` anchor missed them; fixed in airf-rules #896/#900.
- About 1% of coturn-like hosts leak (NetBird, openvidu and mattermost deployments).
- Re-measured 2026-10-12: about 3% of error responders leak.
  - host_variance ~0.94, pointer_rate ~0.79.
  - Entropy is only ~2.6 bits per byte. The pointer runs and per-request variance carry the signal,
    not entropy.
  - The leaked prefix is often `ffffffff` or a `0x7f..` pointer fragment.
- About 14.7k hosts carry `reason_phrase`.
- Leaking hosts have an empty `allocate_software`, so the version boundary needs version-first mode
  (a join to `fingerprint_latest`).
- The skill's regression pair (2026-10-21): coturn scores ~0.007 violation flat and 0.032 in its
  stratum, with pointer rate 0.71. By then it was down to about 150 hosts as 4.10.0 gets upgraded.

**Exposure sources** (subagent, about 10-09):
- Alpine 3.23 and 3.24 community `coturn` is `4.10.0-r0` and unpatched; the secfixes omit this CVE.
- The official `coturn/coturn` image published 4.10.0 tags on 2026-04-14/16. The untagged `latest`
  was 4.10.0 until 4.11.0 shipped on 2026-05-08 (inferred from release dates).
- One leaking cohort (realm `cloudphone`) traces to an open-source fnOS Android-emulator project
  built on Alpine 3.24 with apk coturn.
- Ant Media and Unblu: no bundled coturn found (not verified).

**Verdict.** New CVE.
- VulnCheck is the CNA for coturn.
- On 2026-10-07 all 14 CVEs mapped to coturn 4.10.0 were checked (43915, 53448-53450, 62959, 65981,
  68552-68554, 73212-73216). None is this bug.
- It is distinct from CVE-2026-43994 (OAuth GCM overflow, fixed in 4.10.0), CVE-2026-62959 (ACME HTTP
  heap leak, fixed in 4.15.0) and CVE-2020-4067.

**Outputs.**
- CVE-2026-104074, CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N.
- vulncheck/product#4322 (early) and #4345 (main tracking issue).
- airf-rules #889, #890 and #891, which include `coturn-410-memory-leak`,
  `coturn-software-suppressed` and the TURN Allocate realm/reason rules. #896 and #900 are the anchor
  fixes.
- anchorbreaker #4477 adds the TURN Allocate probe; its targets need ident >= 1.118.0.
- The advisory and GHSA draft were in an old scratchpad and are probably gone.

**Reproduction lab** (session `b5badb55`, 2026-10-16):
- Docker image `coturn-cve-2026-104074:4.10.0` (tag 4.10.0, commit `8e2c5752`, built `-O2 -g` with
  gdb, valgrind and tcpdump).
- A prober and two pcaps in
  `/private/tmp/claude-501/-Users-adampowis-vulncheck-anchorbreaker/b5badb55-55ed-405e-8834-5eb6a697d7a3/scratchpad/coturn-lab`.
  This is a temporary directory and may be gone; rebuild it if needed.
- `leak.pcap` is a natural run and shows an empty reason.
- `leak-seeded.pcap` runs the real vulnerable code path, with the `avalue` region seeded through gdb
  (marker `LEAK:CVE-2026-104074:coturn-stack:` then 474 x `0x2e`). It gives a 508-byte reason in the
  401 response. **It is synthetic and must be labelled as such.**
- We never captured a natural non-zero leak locally.

**Sensitivities.** Never publish real leaked bytes or host IPs. Do not name the customers of a
vendor whose hosts leak.

**Blog angle.** "A TURN probe built for fingerprinting turned out to be a memory-disclosure
detector." A regression that made an error string optional leaked stack, and we found it in scan
data before valgrind proved it.

---

### 2. DrayTek Vigor (DrayOS) OpenVPN UDP/1194 stale-ack memory disclosure (new, no CVE yet)

Full material lives on branch `docs/draytek-openvpn-leak-notes` under
`docs/research/draytek-openvpn-leak/`: README, `blog-outline.md`, `root-cause.md`, `vendor-fix.md`,
`lab/`, `firmware-re/` and `detection/`. This entry summarises it so the series plan can refer to it.

**What it is.** DrayOS's OpenVPN server is DrayTek's own implementation, not stock OpenVPN.

- It answers a `P_CONTROL_HARD_RESET_CLIENT_V2` whose ack-array length byte exceeds the datagram.
- It reads a 4-byte packet id from `frame + acklen_off + 1 + 4*acklen + 8` with no check against the
  datagram length.
- It echoes those 4 bytes as the acked id in its 26-byte server reset.
- The bytes are whatever last sat in the router-wide pooled packet buffer: decrypted VPN traffic,
  plain-HTTP admin sessions from the LAN, syslog lines and inner tunnel IP headers.
- No authentication is needed; one 14-byte datagram triggers it.
- Weakness chain: CWE-130, then CWE-125, then CWE-200.

**How it was found. Our own probe bug was the trigger.**
- `scripts/add_nmap_probes_to_udpx.py` turned the escape `\0` into ASCII `0` (0x30) in about 47 UDP
  probes, shipped in January 2026 (#1131, 2026-01-08).
- The udpx `OpenVPN` probe (`3864c17801b89bcb8f3030303030`) and `OPENVPN_PKI` probe
  (`38010203040506070830303030`) therefore claimed 48 acks (ack length 0x30) and carried only 4 or 3
  bytes.
- They went out once per scan cycle for about nine months.
- The leak-skill sweep on 2026-10-21 (session `db3b0d68`) saw OpenVPN replies that echoed our session
  id but acked a non-zero packet id we never sent. The well-formed udpx `openvpn` probe (session id
  `1212121212121212`) never got one.

**Method.**
1. Passive sweep of `udp_snapshot` on port 1194.
2. Per-cycle variance over 15 days from `udp_staging`, where `ip` is BYTES. The snapshot was the
   wrong source for this check.
3. Source reading of OpenVPN 2.3-2.6, OpenVPN3, SoftEther and glutton. None of them can produce this
   reply: 2.6 sends a hard-coded ack of 0, 2.3-2.5 send `ack_len 0`, and the others drop the packet.
4. A join to `fingerprint_latest`.
5. SNMP sysDescr for firmware versions (model, version and build date).
6. An operator re-probe from an external VM (`openvpn_reprobe.py`, session `e9a3d791`, 2026-10-21).
7. Firmware reverse engineering (session `a6175b62` and others, 2026-10-22).
8. An emulated lab PoC.

**Key numbers.**
- About 21% of ~34k parsed replies acked a non-zero id; host variance ~0.95. 13% of those were 4
  printable ASCII bytes.
- 15-day `udp_staging`:
  - OpenVPN probe: 290,108 hosts, 55,850 non-zero, 97% of them changed between cycles.
  - PKI probe: 185,008 hosts, 53,896 non-zero.
  - Well-formed probe: 349,545 hosts, **0** non-zero.
- 88% of 32,071 HTTP-identified DrayTek hosts leaked, against 22% of the rest. 32,835 non-DrayTek
  leakers had no fingerprint but did have DrayTek's port profile (1194 alone, or 1194 with 500/1723).
- SNMP firmware shows the leak across 3.9.3 to 4.5.3, including September 2026 builds; there is no
  patched boundary. The older Linux-based 1.x Vigor2960/3900 do not run this server.
- **Exposure.** 106,227 distinct hosts leaked at least once in the 30 days 2026-09-20 to 10-20.
  - Top countries: UK 39.6k, NL 13.5k, VN 10.3k, TW 8.0k, AU 6.5k.
  - Top ASNs: Gamma 9.65k, DCBG TW 6.1k, VNPT 5.8k, Wavenet 5.5k, BT 5.3k.
- **Live re-probe** of 16 hosts in 4 classes:
  - 12 of 12 leakers changed their value between two sends 3 s apart.
  - One host returned the same 4 bytes on two different probes, which points to a shared buffer.
  - The well-formed control returned 0 on 16 of 16, and the non-DrayTek controls returned 0.
  - All 4 DrayTek hosts that were passively zero leaked on re-probe. **The 106k is a floor.**
- **Bursts of 12 sends:** the value rolls almost every send. The reads are scattered 4-byte windows,
  not contiguous. Examples include a CRLF (`0d 0a`) and a repeated userspace pointer high word.

**Firmware RE.**
- Vigor3910 v3.9.7.2 is unencrypted. `sohod64.bin` is aarch64 **ILP32**, built `-O0` with its log
  strings intact.
- `openvpn_udp_handler` is at `0x40203548`, found via 60 `__func__` xrefs. `openvpn_build_packet` is
  at `0x401f9d68`.
- 4.x images use a modified ChaCha. The key was recovered from the clear u-boot, but the cipher was
  not cracked, and it was not needed: 3.9.x images carry the same server.

**Lab** (stock QEMU in Docker, synthetic traffic only):
- Gate 2B: a client's plaintext HTTP leaked on 37 of 40 sends. A sweep of acklen 1..255 walks a
  1020-byte pool window and hit the marker in 100 of 255 windows.
- Gate 3 (separate attacker container): 34 of 40 sends leaked, and the sweep hit 232 of 255.
- The router answers about 2,000 probes per second, so one sweep is a contiguous 1020-byte snapshot.
- An idle router leaks its own syslog line.
- Plain-HTTP admin sessions leak as cleartext (login form fields, `SESSION_ID_VIGOR` fragments).
  HTTPS only appears as ciphertext.
- A live one-instruction patch (`0x40203a10: ldr -> b #0x40207544`) answered 0 of 295 malformed
  resets while the tunnel kept working.
- A truncated `acklen=0` reset still over-reads 4 bytes, so a bound on the length is the second half
  of any fix.

**Inner IP header** (2026-11-12, lab):
- Small victim packets let the read window land on the inner IPv4/TCP header. Large packets bury the
  header below the offset-18 floor.
- A public documentation-range destination was recovered.
- This exposes **tunnel addressing and destinations, not the client's public source IP**.
- Two traps hid it at first. A contiguous `c0a8` grep missed it because the aligned 4-byte read
  straddles the address. And large victim packets bury the header.

**Vendor fix.**
- DrayTek sent `V2865_r6955_d90b68ba65.7z` (a Vigor2865 beta) on 2026-10-28.
- It was verified in Ghidra (MIPS BE, base `0x60029418`) and with a Unicorn harness on the real
  handler: 0 of 255 sweep over-reads. A positive control reproduces the leak.
- The fix adds three checks: reject acklen > 8, bound `pid_off+4` by the datagram length, and check
  the UDP length.
- A lab retest end to end needs the same fix on a Vigor3910 build.

**Verdict.** New and unpublished.
- No CVE or DrayTek advisory covers OpenVPN/1194. The nearest relatives are CVE-2025-10547 (web UI)
  and the DRAY:BREAK cluster, all in the web UI.
- Proposed CVSS 3.1 score: 5.3 (AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N), or 5.8 with S:C.
- **No CVE id as of 2026-11-17.** DrayTek is not a CNA.

**Outputs.**
- Disclosed 2026-10-22.
- The AIRF `udp.banner` rule draft is held until the CVE; it cannot version-gate.
- The udpx probe fix (#4704, commit `4caa72cda`, shipped in udpx-v1.39.0 on 2026-10-23) removes the
  trigger from new scan data.
- Blog outline: commit `71bdae70d` (2026-11-05). A Google Doc draft was started in session `d5b0fcff`
  (2026-11-12).

**Sensitivities.**
- Use lab bytes only.
- Say "exposes internal tunnel addressing", not "unmasks public IP".
- Never publish the 4.x key.
- Firmware-decryption web searches tripped the safety classifier, so don't run them.
- Hosts that did not leak are not shown to be safe.

**Blog angle.** "We accidentally fuzzed the internet for nine months."

---

### 3. Cisco IOS IKEv1 notify heap leak: rediscovered CVE-2016-6415 (BENIGNCERTAIN)

Summary page: https://claude.ai/artifact/PEf3uMpGsQzQAXCqDhNWxm (private, IPs redacted).

**What it is.**
- Our IKEv1 Main Mode probe (`buildMainModeV1` in `internal/banners/protocols/ipsec/probes.go`)
  uses initiator cookie `3127fcb038109e89`, is 968 bytes in total, and carries an 840-byte SA payload
  (one proposal with 24 transforms) plus 5 vendor IDs.
- A responder that matches none of our proposals should return an 880-byte Informational (exchange
  5) carrying notify 14, NO-PROPOSAL-CHOSEN, whose data echoes our SA payload.
- Affected devices copy the 12-byte SA header and then send the rest of an 840-byte buffer they
  never filled. That gives about 828 bytes of heap per reply.
- The notify protocol ID is `01` in all 11,167 leaking replies and `00` in clean ones.

**What is in the leaked bytes** (all 11,167 leaking replies, 1-11 Nov):

| Content | Replies | Detail |
|---|---|---|
| Cisco IOS memory-pool block names | 2,599 | `Crypto IKMP` (816), `SADB RootChunk`, `IPSEC If MAP Chunk`, `SADB SA Header`, `IKE FSM`, `String-DB handle`, `Crypto IKEv2`, ... |
| The responder's own IPv4, in binary | 1,257 | inside `01 04 ff ff` address records |
| A copy of our request header | 1,031 | always with our own cookie |
| ASCII IPv4 strings of other parties | 195 | truncated; they look like other IKE initiators, often scanner networks |
| Pointer-shaped 32-bit words | all | 30.6% zero, 5.5% `ffffffff`; high bytes 0x82-0x85 dominate |

- No keys or configuration text have been seen. The window moves, so we cannot rule them out.
- All 289 hosts seen more than once leaked different bytes each time (17 to 175 of 828 bytes
  changed, median 66). That fits live, reused memory.

**How it was found.**
1. The user asked whether BigQuery ML could find weird data. On 2026-11-12 (session `6eb7aeda`) a
   k-means pilot ran with 8 clusters, trained on a 5% hash sample, then `ML.DETECT_ANOMALIES` scored
   one day. It ran on HTTP, SNMP, MSRPC, NetBIOS and IPsec. Nothing needed an Enterprise feature.
2. On IPsec, 509 rows were flagged by both ML and the rule. They were 880-byte IKEv1 Informational
   NO-PROPOSAL-CHOSEN replies with 264-324 trailing zeros and leftover non-printable bytes, spread over
   392 /16s.
3. A plain SQL comparison of `SUBSTR(raw_response,41,840)` against the modal echo, for
   `BYTE_LENGTH=880 AND exch=05`, proved the leak. On 2026-11-11: 76 replies were byte-identical
   echoes, and 970 rows from 958 IPs diverged from byte 13 onward with zeros, `ff` runs and
   pointer-shaped words.
4. **The model ranked the cluster; a byte comparison proved it.** A later claim that the cluster
   "split by byte entropy" was the assistant's reconstruction and was never re-checked.

**Why the 2026-10-12 IKE sweep missed it.**
- That sweep checked declared length against datagram length, and the cookie echo. Both hold for
  these replies.
- More importantly, the trigger did not exist yet. 880-byte notifies were 0 per day from 10-12 to
  10-21, 30 on 10-22, then 700-1,300 per day from 10-23.
- PR #4694 (2026-10-22) replaced the 0x30-corrupted IKEv1 blob with a well-formed Main Mode.
- **Our probe fix began triggering a 2016 bug.** The leak is in the responder; our probe only asks a
  question it answers badly.

**Who leaks.**
- On 11-11, 588 of the 597 fingerprinted leakers were Cisco IOS (98.5%). That is about 2% of 29,734
  IOS IKE responders that day.
- The other 9 are ASA, IP SLA, MikroTik and Windows, likely behind NAT. Cisco says ASA is not
  affected.
- 361 leakers had no fingerprint.
- They sit in many small enterprise and ISP networks, not clouds.
- Over 1-11 Nov: 10,876 IPs (11,167 leaking replies of 11,993 880-byte replies). Daily scans cover
  different IPs, so 11 days reach far more than one day's ~1,000.
- The IOS version split failed. SNMP `sys_descr` exists for 128 of 673,308 IKE responders, and the
  fingerprint version is empty for 29,544 of 29,734 IOS hosts. Only 12.4 stands out (5 of 6 leak).

**CVE reasoning** (session `c3b941ee`, 2026-11-16).
- The Metasploit module `cisco_ike_benigncertain` sends a 2,528-byte Main Mode with one SA (a single
  transform with a 2,436-byte attribute).
- It flags the device as vulnerable if the NO-PROPOSAL-CHOSEN echo differs from what was sent. That
  is our test.
- The oversized attribute only enlarges the echo buffer. Our ordinary 840-byte SA trips the same
  check.
- **CVE-2016-6415**: `cisco-sa-20160916-ikev1`, CSCvb29204 and CSCvb36055. It covers IOS, IOS XE,
  IOS XR 4.3.x-5.2.x and PIX before 7.0; ASA and IKEv2 are not affected.
- It is in VulnCheck KEV (added 2016-09-28) and CISA KEV (added 2023-05-19). Our canaries have seen
  no exploitation.
- The CNA view written on the page: a new CVE is probably not warranted unless a device on a release
  Cisco lists as fixed still leaks. No version data shows that. **The team's decision is not
  recorded.**

**Outputs.**
- vulncheck/product#5221 (filed without IPs).
- anchorbreaker #4921, `feat(ipsec): add ipsec.notify_echo_malformed AIRF target`. Reworked so the
  scanner sets the flag at scan time. A SQL replay flagged 973 of 14,627 NO-PROPOSAL replies on
  11-10. Review found a test-suite bug (negative cases ran against the clean echo).
- airf-rules #1431, `cisco-ios-notify-echo` (Cisco IOS, versionless OS CPE, confidence 30). Merged
  11-12.
- airf-rules #1520 (branch `feat/cisco-ios-benigncertain-cve`, 11-16) adds CVE-2016-6415. **Open.**
- The rule matches nothing until the new zgrab image ships; hosts get the CVE on rescan.
- A backfill would need the target mapped in the source registry.

**Sensitivities.**
- This is a live information disclosure on about 10.9k devices, and the leaked bytes include third
  parties' IPs. Redact carefully.
- The trigger relationship comes from comparing with Metasploit, not from a patched box.

**Blog angle.** "A cheap k-means pilot ranked one odd cluster; a byte comparison proved it was a
2016 NSA-era Cisco leak that our own probe fix had begun to expose."

---

### 4. Cisco IOS PPTP SCCRP hostname leak: rediscovered CVE-2016-6398

**What it is.**
- Cisco IOS PPTP servers leak up to 63 bytes of a previously used packet buffer after the NUL
  terminator in the 64-byte SCCRP hostname field (the VPDN local name).
- CVE-2016-6398, `cisco-sa-20160902-ios`, CSCvb16274, CWE-200, CVSS3 5.3.
- Cisco shipped no fix, only a workaround: set a 64-character VPDN local name.
- NVD's CPE lists only `ios:15.5(3)m`, but the advisory applies to IOS broadly.
- It is not in KEV and has no exploit record.

**How it was found** (2026-10-08, likely session `e1ae17be`, now deleted).
- Leaked MikroTik MNDP TLVs sat in the field's tail and made `target-intelligence:pptp:mikrotik` fire
  on 28 Cisco ports. **A false positive in a rule exposed the foreign bytes.**
- Method:
  - Read `CAST(pptp_snapshot.control_message AS BYTES)`. The hostname is `SUBSTR(b,29,64)` and the
    vendor is `SUBSTR(b,93,64)`.
  - Join `timeline` on `snapshot_hash` with `service='pptp'`.
  - Stay in BYTES; STRING regex functions fail on invalid UTF-8.
  - About $0.02 per query.

**Numbers.**
- 30-day sweep on 2026-10-08: 4,787 of 11,596 Cisco PPTP IPs leak (~41%).
- Only the vendor string `Cisco Systems, Inc.` leaks; every other vendor zero-pads.
- Skill scoring: the Cisco stratum shows a 0.41-0.64 violation rate with host_variance ~1.0 and
  entropy ~3.9. **Protocol-wide the rate is only 0.02-0.026**, which is why the skill scores per
  stratum.

**Verdict.** A known CVE, now detectable. The positive evidence is non-zero bytes after the hostname
NUL on a Cisco-vendor SCCRP.

**Sensitivities: HIGH.** The leaked bytes include router login traffic (Username/Password prompts and
typed usernames), RADIUS AVPs, DNS names, SNMP OIDs and SIP. Never publish bytes or IPs.

**Blog angle.** "A MikroTik rule firing on Cisco routers was the clue: a decade-old, never-fixed bug
leaking router login traffic."

---

### 5. ABB AC500 V2 Modbus FC43 slack: rediscovered CVE-2025-7745

**What it is.**
- ABB AC500 V2 CPUs report VendorName `ABB` or `ABB Stotz Kontakt` and ProductCode 29, 33, 34 or 37.
- On firmware V2.0.6 to V2.5.1 they answer Modbus FC 0x2B/0x0E (Read Device ID) with a 252-byte PDU:
  3 real objects (~34 bytes), then about 218 bytes of stale transmit buffer.
- V2.5.3 and later answer with 34 bytes.

**How it was found.**
- Leak-hunt run 1 on 2026-10-21, over 60 days of Modbus data.
- The tells were MBAP length 254 and entropy/variance on the MEI object values.
- **Aha:** a clean step function from 100% to 0% at V2.5.3.

**Numbers.**
- 32 hosts over 60 days, against about 140 on V2.5.3 or later.
- Slack content:
  - 14 hosts pure `0x33` fill.
  - 18 hosts zeros plus small 16-bit, register-shaped words.
  - At most 2 hosts with printable runs (8 bytes at most).
  - No strings and no credentials.
- One host changed from fill to register data between cycles.

**Verdict.** We rediscovered it and then found it already published.
- ABB advisory 3ADR011432 (2025-07-23, rev 2 2026-05-22), CWE-126, affected <= 2.5.2, fixed in 2.5.3.
- CISA ICSA-26-146-02; credit Reid Wightman (Dragos).
- No public source names FC43 as the trigger; ABB says "unsupported function codes". CVSS C:L is
  correct.

**Why it still mattered.** The product could not see it.
- NVD has no CPE configuration for the CVE.
- `get_cpe_cves` on `o:abb:ac500_cpu_firmware:2.5.1` returns nothing.
- The old `modbus:abb` rule emitted `h:abb:<numeric code>` CPEs.
- airf-rules #1051 (`target-intelligence:modbus:abb-ac500-v2`) builds the CPE from the firmware
  revision and annotates CVE-2025-7745 (<= 2.5.2) and CVE-2022-3192 (< 2.8.6). It hits exactly the
  32 hosts.

**Side finding.** 302 "PM573-ETH V2.7.1" hosts share one identical PDU across 93 /16s, mostly in
Alibaba and Linode ranges. Each answers 16-23 protocols on 100 to 8,200 ports: a honeypot fleet with
an ABB template. The new rule matches them too.

**Gap.** The MBAP frame length is not stored (product#4631), so a rule cannot use the byte-level
tell.

**Blog angle.** "The leak we found had already been found": a clean step is not proof of a new bug,
so search for a CVE first and turn a rediscovery into detection.

---

### 6. Teco Tecomat (SoftPLC) Modbus oversized-exception cross-connection leak (new, candidate CVE)

**What it is.** Teco a.s. Tecomat PLCs (Foxtrot / TC700 family; SoftPLC runtime with the TECO Web
Server) run a Modbus/TCP server on port 502 that returns a malformed oversized exception for any
unsupported function code.

- A compliant Modbus exception is 3 bytes (unit id, function code, exception code).
- The affected firmware instead sets the MBAP length field to 253 or 255 and appends ~250 bytes of a
  transmit buffer.
- The buffer is shared across all client connections, so those trailing bytes are the device's
  previous Modbus response to any client.
- No authentication is needed, and any unsupported function code triggers it.
- Weakness chain: CWE-126 buffer over-read, then CWE-200.

**How it was found.** Leak-hunt run 3 (2026-11-17, the new `modbus` `raw_frame` surface) flagged a
fixed-253-byte exception cohort that was clearly not ABB. Active confirmation the same day (from
sprox-03 and the jumpbox) proved the buffer is shared between connections. Vendor attribution and the
version boundary were pinned on 2026-11-18.

**Method.**
1. Passive sweep of `modbus_parsed` / `raw_frame`: FC 0xAB exceptions with an MBAP length > 3.
2. Cohort isolation on the shared TCP-stack fingerprint (`2732_2_13xx`), which separates the ~29 Teco
   hosts from 915 unrelated hosts that also emit oversized exceptions for other reasons.
3. Active proof: an FC 08 Return Query Data marker planted on connection A reappears at offset 1 of an
   oversized exception read on a separate connection B (24/25 hosts). This firmware's echo is 2 bytes,
   so the controllable marker is 2 bytes - enough to prove cross-connection reuse.
4. Read Device ID (FC 43/14) probed in all access modes (basic / regular / individual-object) - all
   rejected with the same oversized exception, so there is no MEI identity path and the over-read is
   general, not probe-specific.
5. HTTP attribution: response body carries `(c) <year> Teco a.s.`, root redirects to
   `/syswww/login.xml` with a `SoftPLC=` cookie, and `login.xsl` has `author=Teco a.s.`.
6. Web-version vs exception-shape join across the cohort yields the version boundary.
7. `FROM_BASE64(response)` decodes the leaked tails to real content (the `response` field is base64).

**Key numbers and version boundary.**
- 29 distinct affected hosts over 240 days (12-25 per month, May-Nov), a floor - only devices that
  reject the probe reveal the leak. Overwhelmingly Czech and Slovak networks.
- Affected: TECO Web Server v5.7 (MBAP length 255), v6.6 / v7.1 / v7.2 / v7.8 / v9.0 (length 253).
  Not reproduced: v10.3, v10.7 (compliant length-3 exception). The fix landed between v9.0 and v10.3.
- Every unit returns an identical Report Server ID (FC 17): `08 ff e1 40 00 58 00 00`. It is a
  product-line constant, not a per-model value, but it lets Teco map these units to the exact
  CPU/firmware internally.

**What leaks.** Idle devices leak the prior FC 17 identity reply. Actively-polled devices leak the
operator's previous register response - real process/control data. Examples from scan history:
`93.99.130.173` (2026-06-14) leaked ~90 bytes of 16-bit register words; `164.215.127.214`
(2026-10-29) leaked a structured object/register map twice.

**Verdict.** New and apparently unpublished.
- No CPE for `teco` / `tecomat` / `foxtrot` (VulnCheck), and no CVE or advisory found.
- Same vulnerability class as ABB AC500 CVE-2025-7745 (finding 5).
- Proposed CVSS 3.1 score: 5.3 (AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N).
- No CVE id as of 2026-11-18. Teco is not a CNA; VulnCheck could coordinate assignment.

**Outputs.**
- Draft coordinated-disclosure advisory (Claude artifact, 2026-11-18):
  https://claude.ai/artifact/MqN7gAAnkiLQWXFPrgZCqm
- Leak-hunt report: `~/vulncheck/reports/protocol-leak-hunt-2026-11-18.md`.
- No AIRF rule yet: AIRF exposes only `modbus.response` / vendor / product_code / revision, so a rule
  can match the response shape but not the MBAP length or unit id (see product#5338).

**Sensitivities.**
- Leaked register values are operator process data - use sanitised, structural hex only, never live
  victim data.
- Describe the cohort as "a shared Modbus TCP-stack fingerprint"; do not publish the JA4TS string or
  IP-intelligence wording.
- The affected-version band is the observable TECO Web Server version, a proxy for the SoftPLC
  firmware release pending vendor confirmation.
- Hosts that did not leak are not shown to be safe.

**Blog angle.** "The PLC that hands you the last visitor's readings."

---

### 7. Cisco ASA / FTD IKEv1 INVALID-COOKIE stack over-read (new, no CVE yet)

Write-up: https://claude.ai/artifact/E3z8PdbQbfH76FtM2KtsSS (private Claude Doc, no IPs).

**What it is.** One unauthenticated UDP/500 packet makes a Cisco ASA disclose 28 bytes of its own
thread stack, including a pointer into it.

- The trigger is our bare 28-byte IKEv1 Main Mode header (presence probe, cookie
  `3127fcb038109f01`). The ASA has no SA for it and answers with a 68-byte IKEv1 Informational,
  notify 4 (INVALID-COOKIE).
- RFC 2408 expects no notify data there. The ASA sends 28 bytes.
- Root cause (debugger + disassembly, ASA 9.16(4)84 `lina`): the no-SA notify sender passes
  `&hdr_ptr` instead of `hdr_ptr` to the notify builder, which copies 28 bytes from that address. It
  reads past an 8-byte pointer variable into the rest of the frame. CWE-125/126, not uninitialised
  memory.
- A sibling call site directly above uses `mov rcx` (correct) where the buggy one uses `lea rcx`.
  That pair is the static check.

**What is in the leaked bytes** (lab, 9.16(4)84):

| Bytes | Content |
|---|---|
| 0-7 | `hdr_ptr` itself: a stack address of the caller's header copy. Stable per boot, changes on reboot |
| 8-19 | Stale frame slots: other stack or mmap pointers, a `0x12345678` / `0x123456789abcdef0` marker, ASCII clock digits from a per-second task on the same thread stack |
| 20-23 | An offset variable (`0x28` at copy time) |
| 24-27 | Zero |

- The pointer exposes the thread-stack mapping exactly and narrows the libc base to about 22 pages
  on 9.16 (9 on 9.22). The `lina` image base is independent and not derivable.
- Lab watchpoints over full IKEv1 and IKEv2 handshakes saw only pointers, small ints, clock digits and
  the low half of the stack canary written to bytes 8-19. In the lab the canary never reached the
  wire.
- **No key material.** 44 leaks searched against 484 secret values (PSK, nonces, DH values, SKEYID*,
  SK_*): 0 hits.

**How it was found.**
1. A strict-spec Kaitai parse of every `ipsec_staging` row from 2026-10-25 to 2026-11-20 (27.2M
   observations, 11.5M IPs, about $0.10) flagged IKEv1 INVALID-COOKIE and INVALID-MAJOR-VERSION
   notifies that carried data.
2. The data matched nothing we sent: `<ptr64><ptr64><u32> 28000000 00000000`, with x86-64 pointers
   stable per host across scans two weeks apart (30 of 34 pairs).
3. Vendor-ID banners (`CISCO(COPYRIGHT)`, `CISCO-DELETE-REASON`) and full IKEv2 support tied the
   x86-64 shape to modern ASA 9.x.
4. Lab reproduction on ASAv under QEMU on the arm64 Mac (2026-11-20 to 11-23), then gdbstub + lldb
   breakpoints on the copy, then the static check across builds.

**Key numbers.**
- About 4.9k IPs returned non-empty INVALID-COOKIE data (snapshot 2026-11-20): 2,434 on the
  presence probe, 2,505 on the IKEv2 probe answered in v1.
- 84% (presence probe) to 97% (v2 probe) of ASAs that answer IKEv1 leak.
- Shape families: x64 pointers 1,504 IPs (modern ASA); 32-bit LE frame 2,625 IPs (no IKEv2, likely
  legacy 32-bit ASA/PIX, unconfirmed); 29 ASAs echo our header with a little-endian length; a
  `cc`-fill variant on 31.
- Every ASDM-versioned responder leaked (ASDM 7.8(1) to 7.24(10)); no fixed train seen in the field.
  ASDM version is a weak proxy for ASA version.

**Affected builds.**
- Live leak in the lab: ASA 9.16(4)84, 9.22(3)200, 9.24(1)27.
- Static only: FTD 7.6.6-115 `lina` has the identical call site.

**Verdict.** New. Not CVE-2016-6415 (BENIGNCERTAIN, finding 3): Cisco lists ASA as not affected by
that one, and the bug, path and notify type differ. No CVE found for this path.

**Outputs.**
- The write-up above. Lab scripts and SQL in session `da364ae2` scratchpad (temporary).
- No AIRF rule, no product issue, no PSIRT report.

**Sensitivities.**
- Field leaks carry ASLR'd pointers; in 22 of 1,577 field leaks bytes 16-19 have a canary-like low
  byte `00` (about 4x the random rate, unproven). Show lab bytes only.
- Do not publish the libc-distance constants or the measurement recipe.
- Field bytes 16-19 vary on 1,382 of 1,577 x64 leaks, unlike the lab. They are likely return
  addresses (a partial `lina` base leak), but this is unproven.

**Blog angle.** "One wrong ampersand: a firewall that hands every scanner a pointer to its own
stack."

---

## Tier 2: products identified

### 8. OpenClaw AI gateways via mDNS

- **What it is.** mDNS service type `_openclaw-gw._tcp.local.` (legacy `_clawdbot-gw`). TXT records
  carry `gatewayPort=18789` and `role=gateway`; the hostname is `openclaw.local` on about 1,006 hosts.
- **How it was found.** The 2026-10-26 weird sweep over netbios, mdns and bgp (session `0d5f93c9`)
  used a parsed-shape signature, because those tables hold no raw bytes.
- **Sweep numbers.** 1,434 hosts, 183 ASNs, 523 /16s, 41 countries. The top ASN is Hostinger AS47583
  at 33%.
- **Outputs.**
  - airf-rules #1114, `target-intelligence:mdns:openclaw-gateway`. The first mDNS rule in the repo.
    It found 1,048 distinct IPs over 3 days. It emits `cpe:2.3:a:openclaw:openclaw:*` with no version
    (the TXT records carry none), so it gives product detection but no CVE matching.
  - The pivot showed that the existing HTTP rule `initial-access:openclaw` missed 4,138 hosts titled
    "OpenClaw Control". airf-rules #1115 changed its regex to
    `^OpenClaw\b|^(Moltbot|Clawdbot) Control\b`, taking it from 539 to 4,809 IPs (about 8.9x). A plain
    "claw" substring would have false-positived on TeamClaws, GoClaw and others.
- **Showcase slide figures for 22-28 Oct** (session `1ca9e4c5`, artifact
  https://claude.ai/artifact/YJrnsESgudKpgV89CBCfjP):
  - 2,789 hosts, of which 2,757 (98.9%) were missed by the HTTP rule and 490 were in the "previously
    unidentified" pot.
  - 667 CVEs on the CPE, 1 of them KEV (CVE-2026-25253).
  - 47 countries and 266 ASNs (US 883, DE 409, CN 367).
  - 132 hosts still on the pre-rename `_clawdbot-gw`.
  - 56 hosts run a second vulnerable service, 44 of them with a KEV CVE (PHP 19 of 19, Redis 12 of 12,
    MongoDB 4 of 4).
  - 413 canary hits from 143 IPs went after `~/.openclaw/.env` and `openclaw.json` using file-read
    exploits (31 Jul to 16 Sep, 395 of them from Google Cloud).
  - 0 OpenClaw hosts were seen as attackers.
- **Sensitivities.** Customer-facing copy must not say "AIRF" or "IP Intel". The slide renderer
  refuses those words.
- **Blog angle.** "Found in the unknown pot via a service type, and the HTTP rule was missing 89% of
  it."

### 9. Webmin MiniServ UDP discovery reply (udp/10000)

- **What it is.** The reply has the form `host:tcpport:ssl:hostname`, for example
  `0.0.0.0:10000:1:`. MiniServ answers any datagram on its listen port; a subagent confirmed this
  from the `miniserv.pl` source. The 10-22 sweep had left it unidentified.
- **How it was found.** The UDP cross-port shape sweep on 2026-11-12 (sessions `cdc040d4` and
  `4122e715`).
- **Numbers.**
  - 17,880 hosts in 2,942 ASNs; 17,820 after tightening the rule.
  - 99.0% of the UDP responders that also serve HTTP on tcp/10000 send `Server: MiniServ`.
  - About 14k have no TCP Webmin fingerprint.
  - About 228 off-port hosts are genuine Webmin moved to another port.
- **Spin-offs.**
  - The existing Webmin and Usermin recog rules had a `Location ... $` anchor bug. AIRF header order
    is random per scan (a Go map), so the rule matched only when `Location` came last. The fix
    (#1428) newly matches about 38.2k Webmin hosts.
  - New `Server: MiniServ` rules (#1429) add about 57.6k Webmin and 7.5k Usermin hosts.
  - 1,651 hosts sending `MiniServ/0.01` were deliberately left out because they look like decoys.
  - #1430 is the UDP rule (merged). #1432 drops the port gate and excludes the Usermin default port
    20000.
- **Version source (not built yet).** The default theme's login-page cache-busting token (for
  example `?26700109999999999`) maps to the Webmin release for 35 releases (2.100 to 2.670). Webmin
  removed the Server-header version in 2.100 (July 2023). Only 38% of bare-MiniServ ip:ports expose
  the token. The CVE fixed-version claims came from a subagent and are unchecked.
- **Blog angle.** "A 32-byte UDP reply we couldn't name led to 80k newly identified Webmin hosts and
  a header-order bug in our own rules."

### 10. QNAP Hybrid Backup Sync 3 RTRR frame on tcp/8899

- **What it is.** A 24- or 48-byte server-first error frame with magic `abcaa55d`, sent in reply to
  our bare CRLF.
- **How it was identified.**
  - A firmware teardown: QTS 5.2.10 was decrypted with a public third-party script. The user ran it
    after a permission check blocked the agent.
  - The frame is in the `qsync` binary of the HBS 3 package, across six builds.
  - Port 8899 is a Python gateway that forwards anything it does not recognise to the legacy RTRR
    server.
  - This was static analysis only; there was no live capture.
- **Numbers.**
  - 2,072 hosts in 518 ASNs; the rule fires on 1,980 on port 8899.
  - 327 hosts have strong QNAP evidence.
  - Precision is 79% among hosts with any vendor evidence, or 98.5% if router-fronted hosts are set
    aside.
  - 1,108 of the hosts have no other evidence.
- **Outputs.**
  - airf-rules #1434, `qnap-hbs-rtrr`, restricted to port 8899.
  - Report: `/Users/adampowis/vulncheck/reports/qnap-rtrr-tcp8899-2026-11-12.md`.
  - Research directory: `/Users/adampowis/vulncheck/reports/qnap-rtrr-research/`.
  - There is no version, so no CVE attribution. `qnap:hybrid_backup_sync:*` has 8 CVEs, but a
    wildcard version is filtered out of CVE matching.
- **Still open.** 124 hosts send the frame on other ports and 11 answer on every port. The meanings
  of the -1 check, the -111 flag and the status-0 variants are unknown.
- **Blog angle.** "From an unknown 24-byte banner to a Python gateway inside a QNAP app package."

### 11. Smaller identifications

| Shape | Product | Numbers | Follow-up |
|---|---|---|---|
| 8-byte prefix `4c48dbc6ddf6670c` on udp/44818 and 47808 | Juniper (ex-128T) Session Smart Router | 92-97% of the port's responders | Excluded from sweeps. Its CVEs (CVE-2025-21589, CVE-2024-2973) can't be reached by CPE: NVD marks them "Deferred" with empty configurations. |
| BGP hold=0, capability 65 only, private ASN | Check Point Gaia | 26 of 29 fingerprinted; 77 hosts, 27 ASNs | Suppressed as a product family |
| BGP hold=90 with no capabilities, OPEN then Cease | Junos | ~10k hosts | Fingerprint |
| BGP AS_TRANS sent without capability 65 (violates RFC 6793) | Same TCP stack as the Junos bulk | 1,938 peers; 289 share the bogus router id 25.25.25.x, 86-89% in AS135607 | Near-miss (one ISP) |
| tcp/5083 `#ACK` | Traccar device port | - | No rule yet |
| `ff 00*7 01 7f` | ZeroMQ | - | No rule yet |
| tcp/9000 `DB::NetException` | ClickHouse | - | No rule yet |
| tcp/50100 `RIFA` | Rifatron DVR | - | No rule yet |
| udp/7001 `000003e7` | OpenAFS rx version reply | - | No rule yet |
| mDNS `_trim_media` | fnOS NAS (base64 instance names) | 62 hosts, CN | No rule yet |
| mDNS `_mysterium-node` | Mysterium VPN nodes | 61 hosts, 35 ASNs, 17 countries; 1 already labelled proxy | Proxy label candidate |
| mDNS `_vaioncam` | Avigilon cameras | 35 hosts | Near-miss |

---

## Tier 3: honeypots, fleets and fingerprints

### 12. Modbus "Generic Vendor" / "MODBUS-001" fleet

- **What it is.** One byte-identical Read-Device-ID reply: VendorName "Generic Vendor", ProductCode
  "MODBUS-001", revision "01.00".
- It sets more-follows to `0xff` while returning exactly the 3 objects it announced, which a real
  stack would not do.
- **How it was found.** The 10-22 sweep (session `c5c7d042`), function 43, offset 5 = `0x03`; 92% of
  the population has `0x00`. This was the cluster the skill's confounders file had listed as
  "unexplained".
- **Numbers.**
  - 109 hosts, 8 ASNs, 22 /16s over 14 days.
  - AS174 Cogent holds 76% of the hosts seen on the sweep day.
  - IP-intel coverage 0.11 (all from the Initial Access feed).
  - 0 canary hits, 0 fingerprints.
  - First seen no later than 10-09.
- **Verdict.** Honeypot-shaped fleet, medium confidence. It could instead be one operator's sensors
  or a gateway factory default (inference).
- **Blog angle.** "The unexplained cluster, explained by its own placeholder strings."

### 13. DNS-shaped honeypot fleet on non-DNS UDP ports

- **What it is.** 1,784 hosts in Linode, Huawei Cloud and Alibaba return a 12-byte DNS-shaped reply
  on up to 45 non-DNS UDP ports each.
- MongoDB is open on 77% of them and Redis on 48%.
- 357 of them carry an `ics:modbus` label and only 308 carry `honeypot:codesys-v3`. **This is a likely
  source of ICS false positives.**
- No follow-up issue or rule exists yet.

### 14. ABB-template honeypot fleet

See finding 5: 302 "PM573-ETH V2.7.1" hosts.

### 15. Stack fingerprints from the 10-22 sweep

These were promoted as product leads labelled `unknown`, not as IOCs. Draft rules were written but
not seen merged.

| Shape | Hosts | Spread | Reading |
|---|---|---|---|
| IKEv1 Informational with Message ID 0xEEFF0101 | 1,317 | 210 ASNs, 805 /16s | One IKE stack's hard-coded value, sent in reply to our malformed probe. Re-derive after the probe fix. |
| IKE_SA_INIT with Nonce as the first payload | 825 | 56 ASNs, 63% AS5410 Bouygues | ISP-issued CPE firmware (inference) |
| OpenVPN HARD_RESET_SERVER_V2 acking 0x00010000 | 2,174 | 356 ASNs, 1,024 /16s | A constant chosen by the server stack. **Not** the DrayTek leak, which varies per response. |
| SOCKS5 failure reply `05 01 00 03` + zeros | 791 | 335 ASNs, 595 /16s | One open-source SOCKS server library |
| Fixed 32-byte datagram on udp/5683 | 327 | 93 ASNs, 283 /16s | A second constant appeared on 10-23, the day after our probe fix, so the reply is a deterministic function of our probe. Not a host trait. |

### 16. Darklantern UDP echo, rejected as a label signal

- **The idea.** LTE routers infected with Darklantern echo arbitrary UDP, so use the echo as a
  corroborating label signal.
- **What happened.**
  - 21,149 hosts echoed at least one of our 132 probes. 19,332 did so on a single port (RFC 862 echo
    on 7, Bouygues CPE on 3784, Linode on 5683).
  - Only 657 echo on 2 or more ports, and about 280 echo everything.
  - 40% of 563 Darklantern hosts echo on 2 or more ports, but "echoes 2 or more ports" is only 34%
    precise.
  - The echoers are really two deployments: Comcast AS7922 (140 of 147) and Shopee SG AS138341 (37 of
    37). Both have zero TCP fingerprints.
  - Darklantern hosts in every other ASN never echo.
  - Comcast echoers seen on 2 or more days are 81% already labelled, against 0.3% for single-day
    echoers. The missing labels are a dynamic-IP timing effect.
- **Side issue.** Some cloud-ASN hosts labelled `c2:darklantern` (Vultr, TTNET) look like honeypots
  replaying the infosrvd reply. That is a label-quality question.
- **Blog angle.** "Why not to fingerprint malware by a property of the network it sits on."

---

## Tier 4: our own scanner was the weirdest thing in the data

### 17. Corrupted nmap-derived UDP probes (#4704)

- **Cause.** `scripts/add_nmap_probes_to_udpx.py` lines 38-40 dropped the backslash from non-`\x`
  escapes. `\0` went out as `0x30` and `\r\n` as `rn`.
- About 50 of 84 nmap-derived probes shipped corrupted from #1131 (2026-01-08). The ipsec
  `ikev1-main-mode` payload (#3216, 2026-07-06) carried 68 bytes of `0x30`.
- **Effect over 14 days.**
  - 166k hosts echoed RPCCheck.
  - 127k DNS servers returned FORMERR to txid "00".
  - 9k returned `helprnrn`.
  - About 22k IKEv1 "exchange 5" rows a day were error replies to a malformed packet.
- **Fix.** #4704 shipped in udpx-v1.39.0 on 2026-10-23, with a Go drift test and a Python generator
  test.
- **A/B test before the fix.** 4,591 host/port pairs were probed live, up to 60 hosts per cohort,
  with both forms sent 1 s apart.
  - The correct probes won on most protocols. Hosts gained: ONCRPC 57, ARD 50, CIFS NBNS 49/43,
    Kerberos 47, RMCP 39, TFTP 39, version.bind 38.
- **Where the corrupted form won.**
  - L2TP_ICRQ: nmap's own probe is an SCCRQ with tunnel ID 0, which RFC 2661 forbids. We shipped
    tunnel ID 1, which drew 6 SCCRPs.
  - NTP_REQ: servers drop all-zero symmetric-active packets; we shipped root delay `0x10000000`.
  - SIPOptions: a single Korean SIP stack answers only malformed input.
  - IPSEC_START: kept as a permanent exception. The correct form loses 54 of 60 hosts, and 24,391 hosts
    on port 500 are found only by the corrupted one.
- **Also.** About 160k "IKEv1-only" hosts exist only because they answer malformed input with
  PAYLOAD-MALFORMED. They drop every well-formed Main Mode, and a bare 28-byte header keeps them.
- **Consequences, both ways.** The bug triggered the DrayTek leak (finding 2). Fixing it began
  triggering BENIGNCERTAIN (finding 3).

### 18. Probe echo and reflection contamination (product#4816)

- **Measured on 2026-11-05** over all retention (session `797414df`):
  - dnp3: 63% of rows are echoes.
  - rocketmq: 30% (the true count after the fix is 3,462 rows from 1,297 IPs; the first TBW102
    predicate overcounted).
  - codesys V3 TCP: 25% (5,152 genuine against 3,481 echoes, split on L4 meta type `0x83` vs `0xC3`).
  - udp infosrvd: 45%.
  - unknown: our `\r\n` echoed on 922k rows from 26k IPs. 96% of those ip:ports sit on about 1.7k IPs
    that echo on 10 or more ports.
- **Validation trick.** Measure how much a candidate IP set overlaps the hosts that echo `\r\n`
  (rocketmq 69%, controls about 0.1%).
- **Audit of 54 scanners** (2026-11-16, 5 subagents). Seven accepted an echo of our request and
  needed a fix:

  | Scanner | Echo rows | IPs |
  |---|---|---|
  | ntp | 7,967 | 951 |
  | snmp | 1,539 | 268 |
  | stun | 3,266, plus 1,368 Allocate rows | 612 |
  | pptp | 696 | 439 |
  | infosrvd | 948 | 569 |
  | mssql | 48 | 18 |
  | tls | alert-only rows, ~7 a week | - |

  About 40 scanners were clean. A few had a code gap but no affected rows.
- **Fixes.**
  - Scanner: #4896 (TCP `reflected` flag), #4937 (dnp3, rocketmq, codesys), #4943 (ntp, snmp, stun,
    dns), #4944 (pptp, mssql, infosrvd), #4946 (ldap, mqtt).
  - Dataform filters: #4920, #4939, #4945, #4947.
- **Remaining work** is in product#5261.

### 19. A host that replays the previous client's bytes

- **The claim.** Echoed zcrypto ClientHellos arrived on our *plaintext* raw-grab attempt, replaying
  the hello from the preceding TLS attempt.
- **Confirmed live** from sprox-03 on 2026-11-10:
  - The sender's own connection gets 0 bytes.
  - The **next** connection, from any client and any source port, gets the previous payload byte for
    byte.
  - It also replayed a third party's request (a bot's User-Agent GET).
  - A bare `\r\n` and empty connections are not stored or replayed.
- **Consequence.** Our own write log cannot catch third-party replays. The agreed design is a
  nullable `reflected` flag plus a send-nothing re-grab.
- The user challenged the replay claim at first. The assistant admitted it was an inference until the
  live test confirmed it. **This is a good honest-method beat.**

### 20. Other replay and false-row classes found in the same audit

- **BGP OPEN replay.** 622 rows from 599 IPs replay one of four fixed third-party OPENs (hold 90,
  capabilities 1, 2 and 65; documentation-range router ids and private ASNs).
  - 98% of those IPs reflect bytes on other ports, with a median of 203 open ports, against about 0%
    in controls.
  - There is no signal at scan time, so the `bgp_parsed` filter on the exact tuples is permanent.
- **LDAP result 200.** 131,459 rows from 121,688 IPs (28.5% of `ldap_parsed`) stored the client
  library's "connection closed" code as the server's result. That is larger than all the echo issues
  combined. Fixed in #4946, filtered in #4947.
- **socks5 rows before validation.** 715,985 rows from before 2026-08-21 were HTTP servers misfiled as
  SOCKS5 (663,883 start with "HT"). Filtered.
- **mqtt.** 160 bad rows. Do not check CONNACK byte 2's reserved bits: real brokers send `20020402`,
  `20022000` and `20028004`.
- **socks4 `005b000000000000`.** 410,655 rows from 302,428 IPs, 94% on one port, concentrated in
  Alibaba ranges. **Undecided.** It needs an active SOCKS4 probe.
- **TLS alert replay.** Not reproduced; dropped.

### 21. NetBIOS MYSTORAGE unit-id churn: our txid echoed

- **What it looked like.** 111 hosts with the name table MYSTORAGE/WORKGROUP. The first 2 bytes of
  `mac_address` change on every response (347 distinct values in 348 observations, uniform 16-bit);
  the tail `00:21:00:00` is constant.
- **How it was settled.** One external probe with a fixed txid of `0x1234` came back as
  `12:34:00:21:00:00` followed by 58 zeros. The stack copies the txid and the question TYPE into
  UNIT_ID.
- **Verdict.** Benign, closed. Lesson: **a uniform 16-bit head is request echo, not heap memory.**
  The capture backlog is product#4752.
- It also came up in the k-means pilot: 32 of 99 flagged NetBIOS IPs were this cluster.

### 22. DrayTek TCP option kind 30 in JA4TS (unhunted lead)

- Option kind 30 appears on 45 hosts in 94 observations, in the stack
  `25600_2-4-1-1-[1-]<X>_1400_00`, nearly all DrayTek Vigor.
- The trailing byte X takes 255 values across 2,819 hosts and changes between scans. That suggests
  stale or uninitialised SYN-ACK option padding (inference).
- ZMap never offers MPTCP, so this cannot be real MPTCP.
- JA4T keeps only the option kind, so the raw SYN-ACK is needed to hunt it.

---

## Unresolved leads

| Lead | Numbers | Why it matters | Next step |
|---|---|---|---|
| tcp/6001 banner `taurus: /$` | 2,202 Android boxes, 99% Korea Telecom | **Possible unauthenticated shell.** A near-miss on the single-ISP gate. | Confirm from sprox-03, then decide on disclosure. Do not enumerate hosts. |
| tcp/5050 server-first 488-byte random blob | 4,721 hosts, 404 ASNs, KR 60% / US 27% | Unknown protocol | Vendor lookup via timeline |
| tcp/443 single byte `0c` | 2,222 hosts in 26 VPN-hosting ASNs, no fingerprints | Unknown VPN or proxy stack | Active probe |
| tcp/8702 `55ff` / `ffff` | 28,972 hosts, 99.9% KR | Unknown | Vendor lookup |
| tcp/3000 `0000adc3` 564-byte frame | 5,988 hosts, KR | Unknown (GoAhead is a guess) | Vendor lookup |
| tcp/9000 `yesorno` | 2,992 hosts, mostly CN | Unknown | Vendor lookup |
| tcp/9999 fixed text banner | 1,792 DigitalOcean/Vultr droplets | Single-operator tooling? Fails the ASN gate. | Look at content |
| tcp/20202 `OT01` | 27k LG U+ set-tops | One-ISP device | Low priority |
| tcp/8570 `Redirect` | 15.5k Azure hosts | One-cloud service | Low priority |
| 28-byte UDP blob `c000000000000100000000 01ff00001d...` | 352 hosts, 18 ASNs, 71% AS4837, 94% CN; same reply on ports 123, 5353, 9100 and 137 | Answers any probe on 4 ports | Vendor lookup |
| mDNS `_FC9F5ED42C8A._tcp` | 720 Android handsets, 94 ASNs, 45% KT | Leaks the hostname `Android_XXXX` and the WiFi band | Identify the app |
| mDNS `_quantumrc` 2.5.0.19 on port 57120 | 57 hosts, 22 ASNs, 44% KT | Unknown remote-control product | Vendor lookup |
| socks4 `005b000000000000` | 302k IPs | Data quality or real reject? | Active SOCKS4 probe |
| MySQL fixed salts | mongosqld 2.14.x (3 hosts, fixed salt); MariaDB 5.5.65 build (9 hosts) | mongosqld could be a CWE-330 auth-replay candidate | Low priority |
| DrayTek option kind 30 | 2,819 hosts | A second DrayTek stale-bytes hint | Needs raw SYN-ACK capture |
| Other probes corrupted in the old era | Tier 1 candidates: SNMPv1/v3, IKEv1, DCE/RPC, DNS/NBSTAT, Ubiquiti, SqueezeCenter, GTP | Could have triggered other parser bugs like DrayTek's | Data is capped at 32 bytes and can't be recaptured; only re-probing with the old bytes would tell |

---

## Clean negatives (leak hunts)

Every one of these is "clean for the checks run". The IKE result shows a probe change can make a leak
newly visible.

| Protocol | Checked | Why clean |
|---|---|---|
| IKE/IPsec (2026-10-12, ~542k responders) | declared Length vs datagram; cookie echo; Message ID reserved-zero | 100% length match. 447 hosts echoing a non-matching SPI were CSPRNG Informational cookies (host_variance 1.0, but maximally diverse with no memory tells). **Later reversed by findings 3 and 7.** |
| SNMPv3 Report | 40k hosts, all nesting levels | constants or legacy values |
| STUN post-attribute slack, Redis RESP, RTSP, SIP status text | grammar violations | charset only |
| LDAP, Oracle refuse, Postgres errors, telnet | text fields | legacy code pages, ANSI |
| SMB names | UTF-16 decoded byte by byte | our own data-quality bug (#4630) |
| Modbus MEI and exceptions; MQTT return codes | enum and object bytes | MQTT v5 codes |
| socks5 | RSV; REP/ATYP; BND on failure | BND is the host's own IP, RFC1918, or our DST echoed |
| hazelcast | 340 hosts | two int32 list-version counters; a 16-host emulator UUID |
| iec_104 | QDS reserved bits | 0 of 466 objects |
| rocketmq | opaque echo | one build answers a constant 1 |
| nats, rsync, whois, memcached, mongodb, amqp091, ipp, msrpc, mysqlx, managesieve, ajp headers, vnc version | text, UTF-8 | zero violations, or charset only |
| vnc security_types | enum range | Apple ARD 30-36 and UltraVNC 0x68-0x75 are private types |
| rdp ntlm_* | 39k | 33 hosts hit our own UTF-16 decode bug |
| ftp, smtp, imap, pop3 | 229k, 320k, 291k, 204k | GBK, Big5, EUC-KR, Shift-JIS, cp1251, Latin-1; a Sendmail 0x02 template |
| mDNS | 43,850 rows, 6 fields | no control-byte violations; churn affects whole values |
| BGP | version, hold time, notification, capabilities, FQDN | no violations |
| NetBIOS names and flags | 81 of 33,042 non-ASCII | legacy code pages; byte-swapped legal flags |
| Old-era UDP replies (116,604) | everything past byte 32 | **cannot be assessed**: the banner was capped at 32 bytes |
