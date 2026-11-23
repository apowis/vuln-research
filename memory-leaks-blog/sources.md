# Sources

Everything here is local to the research workstation, internal GitHub, or private claude.ai
artifacts. Transcript paths are relative to
`~/.claude/projects/-Users-adampowis-vulncheck-anchorbreaker/` unless another project is named.

**Reading a transcript.** Assistant prose:
`jq -r 'select(.type=="assistant") | .message.content[]? | select(.type=="text") | .text' FILE`.
User prompts:
`jq -r 'select(.type=="user") | .message.content | if type=="string" then . else (.[]? | select(.type=="text") | .text) end' FILE`.

## Sessions by thread

| Date | Session | Thread |
|---|---|---|
| 2026-10-06 | `8bef625a` (deleted) | TURN scanner idea; the Allocate pilot finds bytes after the end of the reason phrase |
| 2026-10-07 | `6bd4aa17`, `6ce70b12` (deleted) | coturn sweep (58 hosts), source and blame, CVE check |
| 2026-10-08 | `e1ae17be`, `9d8959e8` (deleted) | PPTP Cisco leak found through the MikroTik rule; CVSS |
| 2026-10-09 | `f4519ca3` and others (deleted) | coturn attribution and exposure; leak skill PR #4510 |
| 2026-10-16 | `b5badb55` | coturn CVE summary and lab (valgrind, seeded pcap); quotes the deleted sessions |
| 2026-10-21 | `db3b0d68` | Leak hunt run 1: DrayTek signal, ABB, clean negatives |
| 2026-10-21 | `09d73d99` | Leak hunt run 2: clean negatives |
| 2026-10-21 | `e9a3d791` | DrayTek live re-probe |
| 2026-10-21 | `8c702681` (worktree `leak-skill-coverage`) | Leak skill improvements |
| 2026-10-22 | `a6175b62` and DrayTek firmware sessions | Firmware RE, lab gates 1-3 |
| 2026-10-22 | `c5c7d042` and subagents | Weird sweep 1 (20 protocols, 334 clusters, 6 promoted) |
| 2026-10-22 | `f70b2b47` | udpx probe fix #4704 and A/B |
| 2026-10-22 | `5cb65065` | Darklantern echo follow-up (rejected) |
| 2026-10-22 | `e0b6c82c` | Juniper SSR CPE side-thread |
| 2026-10-26 | `ead6da01` | Leak hunt netbios/mdns/bgp; MYSTORAGE |
| 2026-10-26 | `0d5f93c9` | Weird sweep netbios/mdns/bgp; OpenClaw |
| 2026-10-26 | airf-rules `7e1375cd` | OpenClaw rules #1114/#1115 |
| 2026-10-29 | airf-rules `1ca9e4c5` | OpenClaw showcase slide |
| 2026-11-05 | `797414df` | Echo contamination measured |
| 2026-11-05 | airf-rules `91d9c47c` | SOCKS5/3proxy session (mentions CVE-2026-109438) |
| 2026-11-05 | `6ffdfd3a` | DrayTek blog outline committed |
| 2026-11-10 | `6f08fe43` | Cross-connection replay confirmed |
| 2026-11-12 | `cdc040d4`, `4122e715` and subagents | Weird sweep 3: unknown TCP and UDP cross-port shapes |
| 2026-11-12 | `6eb7aeda` and subagents | k-means pilot; IKE notify leak |
| 2026-11-12 | `7982591c` | #4921 review |
| 2026-11-12 | `edb0886e` | DrayTek blog; old-era corrupted-probe leak hunt; inner IP header |
| 2026-11-12 | `d5b0fcff` | DrayTek Google Doc draft |
| 2026-11-12 | airf-rules `f288c44e` | Webmin rules, CI fix #1433 |
| 2026-11-16 | `c3b941ee` | BENIGNCERTAIN comparison, artifact rewrite, CNA reasoning |
| 2026-11-16 | `a76c60e5` (worktree `fix-4816-...`) | Scanner echo audit, fixes #4937-#4947 |
| 2026-11-17 | `f1de4b31` | This collation |

## Local write-ups and artifacts

- **Hunt reports:** `hunts/2026-10-21/hunt-report-2026-10-21.md`, `hunt-followups-2026-10-21.md` and
  `hunts/2026-10-21-run2/hunt-report-2026-10-21-run2.md`.
- **DrayTek:** `hunts/2026-10-21/draytek-openvpn-memory-disclosure.md` (vendor draft) and
  `draytek-openvpn-stale-ack.airf.yaml.draft`.
- **DrayTek firmware work:** `hunts/2026-10-22-draytek-fw/`.
  - `draytek-openvpn-e2e-story.md` is the narrative source.
  - Also `FINDINGS.md`, `ROOT_CAUSE.md`, `DRAYOS-LAB-WRITEUP.md` and `lab/GATE*.md`.
- **DrayTek repo branch:** `docs/draytek-openvpn-leak-notes`, under
  `docs/research/draytek-openvpn-leak/`.
- **QNAP:** `/Users/adampowis/vulncheck/reports/qnap-rtrr-tcp8899-2026-11-12.md` and
  `/Users/adampowis/vulncheck/reports/qnap-rtrr-research/`.
- **IKE / BENIGNCERTAIN page:** https://claude.ai/artifact/PEf3uMpGsQzQAXCqDhNWxm
- **Cisco ASA INVALID-COOKIE write-up:** https://claude.ai/artifact/E3z8PdbQbfH76FtM2KtsSS
- **ASA lab** (temporary, may be gone): session `da364ae2` scratchpad, `asav-lab/`, `asav922/`,
  `asav924/` (QEMU run scripts, probe/kex/watchpoint scripts, SQL `a6-a11.sql`). Memory note
  `asa-ikev1-notify-leak-lab.md`.
- **OpenClaw showcase slide:** https://claude.ai/artifact/YJrnsESgudKpgV89CBCfjP
- **coturn lab** (temporary, may be gone):
  `/private/tmp/claude-501/-Users-adampowis-vulncheck-anchorbreaker/b5badb55-55ed-405e-8834-5eb6a697d7a3/scratchpad/coturn-lab`
- **Memory notes:** `memory/`. The relevant ones are `protocol-leak-hunts.md`,
  `stun-software-nul-padding-and-coverage.md`, `draytek-notes.md`, `ipsec-ike-notes.md`,
  `weird-protocol-sweeps.md`, `echo-contamination-measured-4816.md`,
  `netbios-mystorage-unitid-churn.md` and `udp-protocol-notes.md`.

## Pull requests and issues

**anchorbreaker**

| PR | What |
|---|---|
| #1131 | 2026-01-08; introduced the corrupted nmap probes |
| #4477 | TURN Allocate probe |
| #4510, #4530, #4660, #4665, #4739 | Leak-hunting skill |
| #4678, #4686 | Weird-data skill |
| #4685, #4695 | UDP read-size caps |
| #4694 | ipsec probe rebuild; exposed BENIGNCERTAIN |
| #4704 | udpx correct nmap payloads (commit `4caa72cda`, udpx-v1.39.0) |
| #4896, #4920 | TCP `reflected` flag and its Dataform half |
| #4921 | `ipsec.notify_echo_malformed` AIRF target |
| #4937, #4939, #4941, #4943, #4944, #4945, #4946, #4947 | Echo fixes and Dataform filters |

**airf-rules**

| PR | What |
|---|---|
| #889, #890, #891, #896, #900 | coturn and STUN/TURN rules |
| #1051 | ABB AC500 V2 |
| #1114, #1115 | OpenClaw |
| #1428, #1429, #1430, #1432 | Webmin and Usermin |
| #1431 | `cisco-ios-notify-echo` |
| #1433 | CPE normalisation CI fix |
| #1434 | QNAP HBS RTRR |
| #1520 | CVE-2016-6415 on the IKE rule; **open** |

**vulncheck/product**

| Issue | What |
|---|---|
| #4322, #4345 | coturn |
| #4627-#4633, #4392, #4752 | Capture gaps |
| #4630 | SMB UTF-16 decode |
| #4631 | Modbus MBAP length not stored |
| #4689, #4691 | Probe fix; UDP echo |
| #4816 | Echo contamination (closed) |
| #5221 | IKE notify leak |
| #5261 | Echo follow-ups |
| #5188 | Customer exports |

## Open items that block or shape the series

1. The DrayTek CVE id and advisory.
2. The CNA decision on BENIGNCERTAIN; #1520 merged; the zgrab image with the new target deployed.
3. Active confirmation of the tcp/6001 `taurus` shell.
4. The teammate's account of CVE-2026-109438.
4a. The Teco Tecomat disclosure (finding 6): vendor contact, confirmation of the SoftPLC firmware
    releases behind web versions v5.7-v9.0 and the first fixed build (>= v10.3), and a CVE id.
    Draft advisory artifact: https://claude.ai/artifact/MqN7gAAnkiLQWXFPrgZCqm. Report:
    `~/vulncheck/reports/protocol-leak-hunt-2026-11-18.md`.
4b. The Cisco ASA / FTD disclosure (finding 7): the PSIRT report, a CVE id, and Cisco's affected
    and fixed trains. Nothing is filed yet. Write-up: https://claude.ai/artifact/E3z8PdbQbfH76FtM2KtsSS.
5. Optional, before the "unknown pot" post: vendor lookups on the tcp/5050, 8702, 3000 and 9000
   leads and the c0 UDP blob.
6. Optional: rules for the five minor product IDs (Traccar, ZeroMQ, ClickHouse, Rifatron, OpenAFS),
   so the post can say they are detected.
