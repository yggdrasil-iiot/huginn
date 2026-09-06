# Security policy

## What this project is

Huginn is a **systems-architecture reference implementation**, not a supported product. It is not
distributed as a binary, not published to a package registry, and nobody is running it against a
plant. This policy describes how a security report is handled here; it is not a commercial support
commitment or a CE-marked manufacturer's vulnerability-handling process under the EU Cyber
Resilience Act.

## The part worth attacking

Huginn's job is to **read a capture file and decode industrial protocols out of it**, and every
byte it parses is attacker-influenced by construction. Whoever put traffic on that segment chose
those bytes; whoever handed you the pcap chose the rest. The parsers are hand-written with no
third-party runtime dependency in `pcap`, `decode` or `reconcile`, which is good for auditability
and means there is nobody else's hardening to fall back on.

**In scope, and the reports most worth having:**

- A crafted capture that crashes, hangs, or spins the decoder — link-layer or IPv4 parsing, TCP
  stream reassembly, the Modbus/TCP framer, the S7comm TPKT/COTP/S7 framer.
- **Memory exhaustion.** Reassembled streams are held in memory, post-gap runs included. A capture
  crafted to maximise retained bytes is a real concern and the README says a large capture already
  retains hundreds of MB on ordinary input. A capture that turns that into an out-of-memory kill
  disproportionate to its size is a finding.
- Anything that makes the decoder read outside a buffer, loop without progress, or allocate
  proportional to a length field rather than to the bytes actually present.
- A malformed `CommunicationPolicy` that causes something worse than a clean exit code 2.
- Any path by which running Huginn touches the network. It must not: it reads a file.

**What helps.** The commit, the module, and the input. A minimal `.pcap` attached to the private
report is ideal. If you cannot share the capture, a `ModbusFixtures` / `S7Fixtures` byte sequence
that reproduces it is just as good, since that is how the rest of the suite is written.

## Reporting a vulnerability

Use GitHub's **private vulnerability reporting**: the *Security* tab of this repository →
*Report a vulnerability*. Please do not open a public issue for something exploitable, and please
do not attach a capture containing real plant traffic — reduce it to the frames that matter first.

**What to expect.** Maintained by one person; there is no on-call rotation, so no SLA is promised.
Acknowledgement within a few days, then a fix or a documented decision. If a report goes
unanswered for two weeks, opening a public issue that says only "unacknowledged private report,
see Security tab" is reasonable and will not be treated as bad faith.

## Already known, and by design

These are documented in the README's *What it does not do* and *Honest scope & limitations*, and
in [`samples/README.md`](samples/README.md). They are stated positions, not undisclosed holes.

- **Passive only.** No active scanning, ever. In OT a scan can stop equipment.
- **It reports and does not fix.** No blocking, no correction. Automatic correction amplifies the
  damage when the judgment is wrong.
- **Strict-fit reading after a TCP gap is not resynchronization.** A run that starts mid-frame is
  discarded whole rather than searched for a boundary. This trades misses for false positives on
  purpose, and it means a determined sender can arrange to be under-reported.
- **CONTROL is verified synthetically only** and over-classifies: the eight S7 control function
  codes are classified wholesale because the sub-service string is not parsed.
- **S7comm-plus is not decoded**, which is what S7-1200/1500 speak natively. Neither is Modbus
  FC 43 MEI 13, which stays `UNDECIDABLE` by choice.
- **Judgment is IP-based**, so a bypass behind a serial gateway — different unit IDs on one IP —
  is invisible.
- **`objectRef` is evidence, not judgment.** It never influences the verdict.
- **Not wired to Bifrost.** Huginn reads its own `CommunicationPolicy`; there is no reference to a
  governed registry in its code.

A report that one of these is exploitable in a specific, non-obvious way is welcome. "It does not
detect protocol X" on its own is coverage, and coverage is already reported next to every verdict.

## Out of scope

- **Detection coverage as such.** Undecoded protocols are counted as out of scope in the report
  rather than silently dropped, and unobserved bytes are printed with a percentage. If those
  counters are *wrong*, that is a bug worth reporting; that they are non-zero is the design.
- The sample captures. They are public third-party captures from the 4SICS ICS Lab and are not
  redistributed here — `samples/.gitignore` excludes them.
- Anything requiring write access to the policy file or the machine.
- Third-party findings with no exploit path through this code. `contract` is the only module with
  a third-party runtime dependency (Jackson, to read YAML).

## Supported versions

Pre-1.0. Only `master` is looked at.
