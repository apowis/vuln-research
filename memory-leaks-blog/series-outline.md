# Series outline

The plan has two halves. One long hub piece tells the whole story. Five or six focused posts each
carry one finding or one lesson. Every post links back to the hub. Finding numbers below refer to
[`findings.md`](findings.md).

Publication gates are listed per post. The DrayTek post is the one most blocked: it needs a CVE.

## Recommended order

| Order | Post | Gate | Why this position |
|---|---|---|---|
| 1 | Hub: "Reading the internet's leftovers" | Wording only; it can mention DrayTek as "a router vendor, disclosure in progress" | Sets up the method and the scale before any single bug |
| 2 | coturn CVE-2026-104074 | None (CVE published) | Our own CVE, clean story, safe to show |
| 3 | Old CVEs, new eyes (BENIGNCERTAIN, PPTP, ABB) | CNA decision on BENIGNCERTAIN; airf-rules #1520 merged and deployed | Big numbers (10.9k Cisco), KEV hook |
| 3b | New ICS leak: Teco Tecomat Modbus (finding 6) | Teco disclosure + CVE id | Same Modbus memory-leak class as ABB (finding 5) but a new, unpublished bug; ICS angle, our own disclosure |
| 3c | New Cisco ASA / FTD IKEv1 stack over-read (finding 7) | Cisco PSIRT disclosure + CVE id | Pairs with BENIGNCERTAIN (finding 3): same probe family, a different Cisco product and a new bug; root cause proven to one instruction |
| 4 | The weirdest thing in our data was us | None | Honest, distinctive, sets up the DrayTek twist |
| 5 | Found in the unknown pot (OpenClaw, Webmin, QNAP) | None (avoid "AIRF"/"IP Intel" wording) | Product-detection value; good for marketing |
| 6 | Flagship: We accidentally fuzzed the internet for nine months (DrayTek) | **CVE id and DrayTek advisory** | Strongest story; publish when ready, then link back from the hub |
| 7 (optional) | Teaching the hunt to an agent | None | Method and AI-assisted research angle |

---

## 1. Hub: "Reading the internet's leftovers"

**Thesis.** Our scanner already holds every protocol response it receives. If you read those bytes
for things that shouldn't be there, you find memory leaks, honeypots, unidentified products, and your
own bugs. This was all passive: no extra traffic beyond the routine scan.

**Beats.**
1. **The premise.** Leaks show up as bytes outside a field's grammar. The places to look:
   - after a NUL terminator (PPTP);
   - in an echo field that should mirror our request (IKE, DrayTek ack);
   - as fill beyond the declared objects (ABB);
   - in an error string that should be empty (coturn).
2. **Scoreboard.**
   - 1 new CVE (coturn).
   - 1 new vulnerability in disclosure (DrayTek, 106k hosts).
   - 3 known CVEs made detectable at scale (BENIGNCERTAIN 10.9k, PPTP 4.8k, ABB 32).
   - Products identified: OpenClaw, Webmin, QNAP.
   - Honeypot fleets.
   - A table-by-table clean-up of our own data.
3. **Method in one picture.** A pipeline: catalogue each field's grammar, run BYTES-level SQL
   recipes, score per vendor or version stratum, run a passive temporal check, confirm with one
   active probe, search for an existing CVE, then disclose and/or write a detection rule.
4. **The two twists:**
   - Our broken probe found DrayTek.
   - Fixing our probes began triggering BENIGNCERTAIN.
5. **What we can't see.** HTTP and TLS are not covered. UDP replies were capped at 32 bytes. Parsed-
   only tables hold no raw bytes. A clean result is "clean for the checks we ran".
6. **Series index.**

**Figures.**
- A field-grammar diagram showing where leaks hide, across the five shapes.
- The scoreboard table.
- The daily count of 880-byte IKE notifies (0, then 30, then ~1,000 a day around the 10-22 probe fix).

---

## 2. "A fingerprinting probe that found a CVE": coturn CVE-2026-104074 (finding 1)

**Beats.**
1. **The goal.** Attribute STUN servers that send no SOFTWARE attribute, by sending a TURN Allocate.
2. **What we saw.** The 401 response's reason phrase held bytes after the text should have ended.
3. **Sweep.** 58 hosts with stable leak shapes. Pointer-shaped prefixes (`ffffffff`, `0x7f..`). Low
   entropy (~2.6 bits per byte) but high per-request variance. Explain why entropy was the wrong tell.
4. **Source.** Commit `20d8e382` made the reason optional and skipped the copy without zeroing the
   buffer. The missing memset came back in 4.11.0 via fuzzing PR #1878. A regression of the
   CVE-2020-4067 class.
5. **Proof.** Valgrind on tag 4.10.0 flags `strlen` on uninitialised memory. Why many vulnerable hosts
   send an empty reason (zero stack residue), and what that means for counting.
6. **Exposure.** Alpine 3.23/3.24 `coturn 4.10.0-r0`, the official image's `latest` from mid-April to
   May 2026, and downstream bundles.
7. **Disclosure.** VulnCheck as CNA; the fix had already shipped silently in 4.11.0.
8. **Detection.** AIRF rule; 4.10.0 doubles as a precise version fingerprint. Note the anchor miss (5
   of 58 hosts start with a printable byte).

**Figures.**
- An annotated 401 response. Use the **seeded lab pcap only, labelled synthetic**.
- A version timeline: 4.10.0 released, then 4.11.0 fix, then Alpine still shipping 4.10.0.

**Gate.** None. Check CVE-record wording against the published record.

---

## 3. "Old CVEs, new eyes" (findings 3, 4, 5)

**Thesis.** Rediscovery is a result too. A known bug you can't see in your data is a blind spot. The
skill's rule: search for an existing CVE before planning disclosure, then turn the rediscovery into
detection.

**Beats.**
1. **BENIGNCERTAIN (CVE-2016-6415).**
   - The k-means pilot flagged one cluster of 880-byte IKE replies.
   - A byte comparison against the expected echo proved it was heap memory.
   - What the leaked bytes contain: IOS pool names, pointers, the device's own address, other peers'
     addresses.
   - The bytes differ every scan, on all 289 repeat hosts.
   - The Metasploit comparison: same check, smaller SA.
   - 10,876 IPs, 98.5% IOS. An exploited KEV, still live ten years on.
   - **Twist: our probe fix on 10-22 is what started triggering it.**
2. **Cisco PPTP (CVE-2016-6398).**
   - A MikroTik rule fired on Cisco routers because MNDP bytes had leaked into the hostname field.
   - About 41% of Cisco PPTP servers leak.
   - Cisco never shipped a fix, only a workaround.
   - Content classes (login prompts, RADIUS). **Describe the classes only; no bytes.**
3. **ABB AC500 (CVE-2025-7745).**
   - A clean step from 252 to 34 bytes at V2.5.3. It looked like a new bug and was already published
     (Dragos).
   - NVD had no CPE configuration, so our product could not attribute it until the rule.
4. **Lessons.**
   - Per-stratum scoring: PPTP is 0.02 flat but 0.58 among Cisco hosts.
   - Clean negatives expire when probes change.
   - Any detection fed by NVD alone misses CVEs whose configurations are empty.

**Figures.**
- The annotated IKE reply. Reuse the artifact's legend, with the responder address redacted.
- A table of leaked-content classes.
- The ABB step chart: reply size against firmware version.

**Gate.** The CNA decision on whether BENIGNCERTAIN gets a new CVE (only if a version Cisco lists as
fixed still leaks). airf-rules #1520 merged and the zgrab image with `notify_echo_malformed`
deployed. Version data is thin, so be careful with "unpatched" claims.

---

## 4. "The weirdest thing in our data was us" (findings 17-21)

**Thesis.** When you hunt for anomalies, the first and biggest anomaly is your own scanner. Say this
up front; it makes everything else credible.

**Beats.**
1. **One missing backslash.**
   - The nmap probe import sent `\0` as `0x30` in about 50 UDP probes for nine months.
   - The symptoms: 166k RPC echo hosts, 127k DNS FORMERR replies, `helprnrn`.
2. **The A/B test.**
   - Correct probes found more hosts on most protocols.
   - The exceptions where the broken probe won: IPsec (24k hosts only answer malformed input), a
     Korean SIP stack, NTP, and L2TP, where nmap's own probe breaks the RFC.
3. **Echoes.**
   - dnp3 63%, rocketmq 30% and codesys 25% of rows were our own requests reflected back.
   - The audit of 54 scanners: 7 accepted an echo.
4. **The replay host.**
   - A host that hands the next client whatever the previous client sent, including another
     scanner's request.
   - Our write log can't catch that. The `reflected` flag design.
5. **Third-party BGP OPEN replays.** LDAP "result 200" (28.5% of a table). socks5 rows that were
   really HTTP.
6. **The pay-off.** The bug that polluted our tables also found the DrayTek leak (tease post 6).
   Fixing it exposed BENIGNCERTAIN (link post 3).
7. **Takeaways for other scanner operators.**
   - Validate the reply type and direction.
   - Compare against all bytes you sent across the task.
   - Measure overlap with known echo hosts.

**Figures.**
- The probe hexdump before and after the fix.
- A bar chart of echo share by table.
- A sequence diagram of the replay host: connection A sends X, connection B receives X.

**Gate.** None. Keep the replay host anonymous.

---

## 5. "Found in the unknown pot" (findings 8-16)

**Thesis.** A rare response shape repeated across unrelated networks is usually a product, sometimes
a honeypot fleet, and occasionally something worse. The shape sweeps turned unidentified hosts into
named ones.

**Beats.**
1. **OpenClaw.**
   - An mDNS service type exposed 1,434 AI gateways (2,789 a week later).
   - The existing HTTP rule missed 98.9% of them.
   - 1 KEV on the CPE. Canary hits went after `~/.openclaw/.env`. 44 hosts run a second KEV-affected
     service.
2. **Webmin.**
   - A 32-byte UDP reply led to the source and to 17.9k hosts.
   - A header-order bug in our own rules, newly matching 38k hosts, for about 80k+ new Webmin and
     Usermin overall.
   - A version token is in the login page.
3. **QNAP.** A 24-byte frame on 8899 traced through a firmware teardown to HBS 3's RTRR gateway.
4. **Honeypots.**
   - The "Generic Vendor / MODBUS-001" fleet (76% Cogent).
   - The DNS-shaped fleet answering 45 ports, some of it labelled as ICS.
   - The ABB-template fleet.
   - How to tell a decoy from a device.
5. **Near-misses and what we rejected.** Darklantern echo as a malware signal (34% precise; really
   two ISPs). Set-top boxes with one ISP's service types.
6. **Optional, only if confirmed.** The tcp/6001 `taurus` shell prompt on 2,202 devices.

**Figures.**
- Cluster cards: shape, host count, ASN spread and verdict.
- An OpenClaw world map, or a country bar chart.

**Gate.** Wording: no "AIRF" or "IP Intel" in customer-facing copy. The `taurus` item needs
confirmation and possibly disclosure first.

---

## 6. Flagship: "We accidentally fuzzed the internet for nine months" (finding 2)

The outline already exists: `docs/research/draytek-openvpn-leak/blog-outline.md` on branch
`docs/draytek-openvpn-leak-notes` (12 sections, FortiGate-post style). A Google Doc draft was
started on 2026-11-12. Do not duplicate it here; link it from the hub when it is published.

**Beats in brief.**
1. The broken probe.
2. The scan-data signal: a non-zero ack that changes every cycle, never seen from the well-formed
   probe.
3. Good probe against bad, sent live.
4. Firmware RE: the ack-array read with no bounds check.
5. The emulated lab: other users' decrypted traffic, admin sessions and inner IP headers.
6. A live patch, and DrayTek's fix.
7. Exposure: 106k hosts, a floor.

**Gate.** A CVE id and the DrayTek advisory link. Also screenshots and the detection rule.

---

## 7. Optional: "Teaching the hunt to an agent"

**Thesis.** The hunts were run by Claude Code agents with two skills that hold field-grammar
catalogues, SQL recipes, scoring, known-positive regressions and decoys. What worked and what didn't.

**Beats.**
1. **Skill structure.** Phases 0-5, `catalog.yaml`, confounders, noise registry, disclosure
   checklist, blind spots.
2. **Calibration.**
   - Two real leaks must rank first: coturn and PPTP.
   - Six decoys must not rank: SNMP GBK, IPsec CSPRNG cookies, and others.
3. **Lessons.**
   - Entropy lies (reused-buffer leaks run at 2.6-3.9 bits per byte).
   - Stratify scores by vendor or version.
   - Stay in BYTES.
   - Run synthetic controls first.
   - Check cost gates; one missing DISTINCT turned into a 270k fan-out.
4. **Where the agent was wrong.**
   - The "Darklantern signal" was overturned by its own follow-up.
   - The replay claim was an inference until a live test.
   - An "entropy split" was a reconstruction.
   - A first IKE "clean" result expired.
5. **k-means verdict.**
   - Cheap (cents) and not Enterprise-gated.
   - Ranked mostly by length, and added little over rules.
   - Its one real contribution was a structural cluster that a byte comparison then proved.
6. **Cost.**
   - Most sweeps cost $0.35 to $2.40.
   - A /16-bucket geo join cost $0.02 against $0.42-$0.73 for the prefix cross join.

**Gate.** Internal sign-off on discussing the tooling publicly.
