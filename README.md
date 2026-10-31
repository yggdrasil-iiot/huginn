# Huginn

[![CI](https://github.com/yggdrasil-iiot/huginn/actions/workflows/ci.yml/badge.svg)](https://github.com/yggdrasil-iiot/huginn/actions/workflows/ci.yml)
![Java](https://img.shields.io/badge/Java-17-orange?logo=openjdk&logoColor=white)
![Build](https://img.shields.io/badge/build-Maven%20multi--module-blue)
![Tests](https://img.shields.io/badge/tests-313-brightgreen)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache_2.0-blue.svg)](LICENSE)

**The observation-and-reconciliation arm of the [Yggdrasil](https://github.com/yggdrasil-iiot) IIoT spine — it compares what was *declared* against what actually crossed the wire.** Reads Modbus/TCP and S7comm from pcap captures; from Zeek ICSNPP logs it also reads S7comm-plus.

> **Fail-closed only stops what goes through the gate. Huginn sees what didn't.**

[Bifrost](https://github.com/yggdrasil-iiot/bifrost) declares *what may cross the OT/IT boundary*, and a pre-merge gate plus the runtime edge (Heimdall) enforce it. But an engineering workstation wired straight to a PLC, an unregistered device on the segment, a path around the broker — none of those pass through the gate, so nothing knows about them. Huginn reads a pcap, decodes the industrial traffic that actually flowed, and **reconciles it against the declared communication policy** to find undeclared communication.

Commercial OT monitoring has to derive "normal" from the traffic itself — a **learned** behavioural baseline, generally alongside signatures and protocol-aware rules — because there is no declaration to compare against. In the Yggdrasil family the **contract is the allowlist**, so this compares instead: no model to train, no baseline to tune.

```
declare (Bifrost) → enforce (gate · Heimdall) → observe (Huginn) → reconcile (Huginn)
   what may            block it at              what actually        difference =
   cross                the gate                 crossed              bypass
```

## In IEC 62443 terms

62443 divides a plant into **zones** and the **conduits** between them, and the operational
requirement is not a drawing made once. Guidance describes a **living list of every communication
path** — protocol, frequency, affected assets, responsibilities — and notes that auditors
explicitly ask for it. SR 6.2, continuous monitoring, is the same idea in the system requirements.

**Huginn produces the observed half of that list, and reconciles it against the declared half.**
Its output is one row per undeclared path: who talked to whom, over which protocol, doing what,
touching which object.

The difference from how this is usually done is the whole point. The prevailing practice is to
*baseline* normal traffic and alert on deviation, because nobody declared the conduits in the
first place. Signatures and protocol-aware rules sit alongside that baseline in a real product,
but the baseline is the part that has to be **learned**, and it is the part a declaration
replaces. Here the conduits are declared — a deny-by-default `CommunicationPolicy` — so Huginn
compares rather than learns. **There is no model to train, and no baseline that can drift,
because there is no baseline.** A conduit that was never declared is a finding on the first
packet, not after a learning window.

What it does not yet give a real conduit register: **frequency** (a finding says a path exists,
not how often it is used), **ownership** (not derivable from traffic — it has to come from the
declaration side), and any conduit carried by a protocol it does not decode, which is counted as
out of scope rather than enumerated. Those gaps and what would force them are written up in
[Bifrost's `docs/ENTERPRISE.md` §5](https://github.com/yggdrasil-iiot/bifrost/blob/main/docs/ENTERPRISE.md#5-conduit-inventory).

This is a way of describing what the tool does, not a conformance claim. There is no
certification here, and 62443-3-3 asks for a great deal more than one register.

## Usage

```bash
mvn -DskipTests package
java -jar cli/target/huginn.jar capture.pcap examples/policy.yaml
```

Exit codes: **0** no violations · **1** violations found · **2** usage, input, or contract error. **A large `UNDECIDABLE` count still exits 0 when there are no violations** — coverage is always reported, so the exit code does not have to carry it too.

**Where the policy comes from.** You write it — or, for the equipment Bifrost governs, project it: `gates conduit-project <registry> --edge <ip> --bind <equipment>=<ip>` emits a fragment in exactly this format saying the governed edge is the only permitted writer of that equipment, and Huginn reads it unchanged (no Huginn code knows Bifrost exists; a file crosses, nothing else). Two things about that fragment are stated in its own header and are worth repeating here: the equipment-to-address binding is **declared by a person**, not discovered on the wire, and it is a **fragment** — it says who may *write*, not who may legitimately *read*, so merge it into the site policy rather than running it alone. A write to governed equipment from any other host, over a protocol the edge does not even speak, is then the bypass this tool exists to find. Proved end-to-end against a 4SICS capture by Bifrost's [`run-huginn-seam-gate.sh`](https://github.com/yggdrasil-iiot/bifrost/blob/main/scripts/run-huginn-seam-gate.sh).

The policy is deny-by-default. Only what is written is allowed ([`examples/policy.yaml`](examples/policy.yaml)):

```yaml
version: 1
peers:
  - id: hmi-01
    address: 10.0.1.20
  - id: plc-mixer
    address: 10.0.2.11
allowed:
  - from: hmi-01
    to: plc-mixer
    protocol: MODBUS_TCP
    access: [READ, WRITE]
```

The report carries **coverage alongside violations**. Without it, "0 violations" could mean *clean* or *we read almost nothing*.

```
Huginn — 통신 대사 결과
  처리 패킷            246,137        packets processed
  대상 외 패킷          37,197        packets out of scope
  해독한 대화                2        conversations decoded
  대상 외 대화           7,288        conversations out of scope
  UNDECIDABLE 대화           0        conversations we could not judge
  UNDECIDABLE 관찰           1        observations we could not judge
  미관측 바이트         85,525 (2.4%) bytes we never saw

  프로토콜        해독 대화  UNDEC 대화        관찰  UNDEC 관찰       미관측 바이트
  MODBUS_TCP             0           0           0           0           0 (0.0%)
  S7COMM                 2           0      23,733           1      85,525 (2.4%)

위반 23건                             23 violations
  [HIGH] 10.10.10.30:49152 → 10.10.10.10:102  S7COMM WRITE  sym:m/16
```

> Report text is Korean; the annotations above are for this README only. Set `chcp 65001` and run with `-Dstdout.encoding=UTF-8` on Windows, where the console defaults to cp949.

Three numbers answer three different questions, and none substitutes for another: **`UNDECIDABLE` conversations** are traffic we read but could not judge, **`UNDECIDABLE` observations** are individual requests we could not classify, and **unobserved bytes** are what we never saw at all — bytes missing from the capture plus bytes we received but could not frame. The per-protocol table exists because a summed report hides how thin one protocol is in a capture dominated by another.

### From Zeek ICSNPP logs

```bash
java -jar cli/target/huginn.jar --zeek-log s7comm.log --zeek-log s7comm_plus.log --zeek-log modbus_detailed.log policy.yaml
```

Many OT monitoring stacks already run Zeek with ICSNPP (for example Malcolm or Security Onion), so Huginn reads what the site already produces rather than adding a parser. The main gain is **S7comm-plus** (the protocol of newer S7-1200/1500 firmware), which Huginn's own decoder does not parse, observed from `s7comm_plus.log`. Huginn's own decoder is unchanged, and reconciliation against the policy uses the same `Reconciler`.

- Pass one or more `--zeek-log <file>` pairs, followed by the policy as the last argument. The `huginn <capture.pcap> <policy.yaml>` form is unchanged, and so are the exit codes.
- Directories are not accepted, so rotated copies or overlapping exports cannot be counted twice. Giving the same file twice is refused (exit 2).
- Files are recognized by their `#path` header (`s7comm`, `s7comm_plus`, `modbus_detailed`), not by file name. Any other `#path` is refused (exit 2). Only Zeek's ASCII TSV format is read; JSON-lines logs are refused with a message to run Zeek with `LogAscii::use_json=F` (the default).
- Header declarations (`#separator`, `#unset_field`, `#empty_field`) are honoured rather than assumed. Columns are read by name, so reordered or extra columns are fine; a missing column Huginn uses, or a changed `#types` for it, is refused (exit 2) naming the column.
- Pinned versions (ICSNPP has no tagged releases): cisagov/icsnpp-s7comm `102a35c` (2026-10-22), cisagov/icsnpp-modbus `6dd3dab` (2026-10-17), Zeek 9.0.1.

The policy gains a protocol name, **`S7COMM_PLUS`**, separate from `S7COMM`. Folding them together would let an `S7COMM: [READ]` rule written for an S7-300 silently allow S7comm-plus reads to an S7-1500. The policy stays `version: 1`, so existing policies read unchanged. Bifrost's projection keeps emitting `S7COMM`; nothing in Bifrost changed.

Only requests become observations, as on the pcap path:

- `s7comm.log`: ROSCTR 1 (Job) is a request; ROSCTR 2 and 3 are responses. Endpoints come from `source_h/source_p → destination_h/destination_p` (ICSNPP's true-sender columns), not `id.orig_*`. Access uses the same `S7Access` table as the pcap path. The log has no variable addresses, so `objectRef` is `fc:4` / `fc:5` for read/write, the existing control names (`plc-stop`, `upload-start`, …) for control functions, and PLC Control carries the service name ICSNPP logged, e.g. `plc-control (PLC Start / Stop)`. User-Data (ROSCTR 7) requests (function `0x4X`) become `UNDECIDABLE` with an `objectRef` like `userdata:Request: CPU Functions/Read SZL`, because the pcap path does not interpret User-Data either; `0x8X` rows are responses.
- `s7comm_plus.log`: only opcode `0x31` (Request) is observed; `0x32` responses and `0x33` notifications (sent by the PLC) are not. The new `S7PlusAccess` table in `decode`: READ = Get Multi Variables `0x054c`, Get Variable Sub Streamed `0x0586`, Explore `0x04bb`; WRITE = Set Variable `0x04f2`, Set Multi Variables `0x0542`; UNDECIDABLE = Create Object `0x04ca` (also the first message of every session), Delete Object `0x04d4`, Begin Sequence `0x0556`, End Sequence `0x0560`, Invoke `0x056b`, Get Link `0x0524`. WRITE is a floor: CPU run/stop on S7-1200/1500 is also carried as Set Variable on a CPU object, and the log has no object ids to tell them apart. `objectRef` is `fn:<function_name>`, e.g. `fn:Set Variable`.
- `modbus_detailed.log`: a row is a transaction, not a packet; ICSNPP pairs request and response by transaction id. There is no direction column; the source is `id.orig_*`. `matched=T` means a request was seen: one observation. `matched=F` with request columns (`address`, `quantity`, `request_values`, `request_subfunction_code`, `request_data`) is a lone request: one observation; without them, direction is unknown. Functions ICSNPP does not handle specially (FC 7, 11, 12, 17 …) get one header-only row per message: two consecutive rows with the same connection, transaction id and function are one request; a lone row is direction unknown. Exception responses with no paired request are direction unknown. Function names map to codes through Zeek's own `Modbus::function_codes` table, then the same `ModbusAccess` / `ModbusObjectRef` as the pcap path, so `holding:40001` notation is identical. FC 43 is READ only when `mei_type` is exactly `Read Device Identification`. The log has no FC 23 address and no Read Device ID code, so those show as `fc:23` / `fc:43`.
- Rows whose direction cannot be decided produce no invented observation: **one `UNDECIDABLE` per connection**, the same place a one-directional conversation lands on the pcap path.

Violations are listed exactly as for pcap. Coverage differs: a log has no packet, byte or conversation counts, so the report does not print them. It accounts for every row instead — rows = request rows + response/notification rows + direction-unknown rows. The ICSNPP `s7comm_plus.pcap` trace's logs, both protocols declared:

```
Huginn — 통신 대사 결과 (Zeek 로그)
  읽은 로그 파일             2        files read
  읽은 행                  155        rows read
  요청 행                   51        request rows
  응답·알림 행             104        response / notification rows
  방향 미확정 행             0        direction-unknown rows
  관찰                      51        observations
  UNDECIDABLE 관찰           1        observations we could not judge
  패킷·바이트 커버리지 없음 — 로그에 없는 통신은 이 수에도 없다
                                      no packet/byte coverage — what is not in the log is not in these numbers either

  로그             프로토콜               행       요청  응답·알림     미확정       관찰  UNDEC 관찰
  s7comm           S7COMM               34         17         17          0         17           1
  s7comm_plus      S7COMM_PLUS         121         34         87          0         34           0

위반 없음                             no violations
```

The log path judges what is in the log; [`samples/README.md`](samples/README.md) compares it with the pcap path on the 4SICS captures.

## Principles — and the tests that hold them

| Claim | Test |
|---|---|
| Protocol is decided by **framing, not by port** — whoever bypasses changes the port | `ModbusFramerTest.protocolId가_0이_아니면_프레임이_아니다` · `EndToEndTest.포트가_502여도_프레이밍이_아니면_Modbus로_치지_않는다` |
| Direction is decided by **PDU shape, not by port** — port heuristics cannot separate mirror images | `ModbusObserverTest.서버_포트가_더_높아도_형태로_판정한다` · `클라이언트가_특권_포트를_바인딩해도_형태로_판정한다` |
| S7 needs no signal combination at all — **ROSCTR declares request vs response** | `S7DecoderTest.응답만_잡힌_캡처는_판정하지_않는다` · `양쪽_방향에_모두_요청이_있으면_판정하지_않는다` |
| **Only requests become observations** — observing responses turns normal traffic into violations | `ModbusObserverTest.요청만_Observation이_된다` |
| A one-directional capture is **not assumed** to be requests | `ModbusObserverTest.한_방향만_잡힌_캡처는_요청으로_단정하지_않는다` |
| When SYN and PDU shape disagree, **neither is trusted** | `ModbusObserverTest.SYN과_형태가_어긋나면_판정하지_않는다` |
| Unknown function codes are not quietly read as READ — FC 43 is READ **only for MEI 14**; MEI 13 carries both reads and writes and stays `UNDECIDABLE` | `ModbusAccessTest.장치식별_조회는_읽기다` · `CANopen_전송은_여전히_UNDECIDABLE이다` |
| Non-industrial streams are **out of scope**, not `UNDECIDABLE` | `EndToEndTest.비산업_트래픽은_UNDECIDABLE이_아니라_대상_외로_센다` |
| After a TCP gap, a run is accepted **only if it frames cleanly end to end** — a run starting mid-frame is discarded whole | `RunReaderTest.이후_구간은_잔여가_0일_때만_받는다` |
| **No byte sequence satisfies both framers** — verified exhaustively over all 65,536 values of the one contradictory field, running the real framers | `CoexistenceTest.어떤_바이트열도_두_프레이머에_동시에_걸리지_않는다` |
| The three conversation counters **sum to the total** — no conversation is uncounted or double-counted | `ModbusObserverTest.대화_수는_세_계수의_합과_같다` |
| Same input, same report | `EndToEndTest.같은_입력에_같은_리포트가_나온다` |
| **S7comm-plus is its own policy name** — an `S7COMM` rule does not cover it | `PolicyReconcileIntegrationTest.S7COMM_허용은_S7COMM_PLUS_를_허용하지_않는다` · `ZeekEndToEndTest.S7COMM_선언은_S7comm_plus_를_덮지_않는다` |
| **The same request read from a pcap and from a Zeek log is judged the same** | `IcsnppCrossCheckTest.snap7_은_두_길이_같은_요청을_같게_판정한다` · `modbus_example_은_대상_표기까지_같다` |
| Violations are actually caught — 0 findings on clean input proves nothing | `EndToEndTest.미등록_장비의_쓰기를_잡는다` · `미등록_호스트가_PLC를_정지시키면_HIGH로_잡는다` |

## Validated against real captures

Cross-checked against **tshark 4.6.8** on three [4SICS ICS Lab](https://www.netresec.com/?page=PCAP4SICS) captures (2.3M / 1.25M / 246K packets). Huginn judges by framing, tshark by port — when they agree, each is a falsification attempt against the other.

| Check | tshark | Huginn | |
|---|---:|---:|---|
| Total frames · non-TCP packets (151020) | 246,137 · 37,197 | 246,137 · 37,197 | match |
| Modbus request packets (151022) | 49,767 | 49,767 | match |
| S7 requests, ROSCTR 1 (all three) | 23,732 / 86,403 / 53,217 | 23,732 / 86,403 / 53,217 | **exact** |
| Responses (Modbus 49,787 · S7 76,951) | — | **0 observed** | by design |
| 1200SYM addresses (151020) | `area2 0x0052` · LID 16×9 · 17×1 · 18×8 | `sym:m/16`×9 · `sym:m/17`×1 · `sym:m/18`×8 | field-level match |
| FC 43 device identification (151022) | `read_device_id` 1 ×19 · 2 ×5 | 19 · 2 reported | consistent |

That last row counts *findings*, not packets: the three unreported device-ID-2 requests went to peers the policy declares, so they are allowed and produce no finding. Every other row compares like with like.

Findings on real data include an **unregistered host writing to a PLC over S7** and a **device-enumeration sweep** — one host probing six PLCs in turn with Read Device Identification.

Two further cross-checks compare the pcap path with the Zeek-log path. On ICSNPP's own traces, the judged requests (READ/WRITE/CONTROL) are identical on both paths, differing only in timestamps, `UNDECIDABLE`, and target notation the log does not carry; CI runs this on every build. On the 4SICS captures the logs hold fewer requests than the wire: on 151020 `s7comm.log` almost stops after the first ~50 minutes of a 6.6-hour connection; on 151021 five Read Device Identification requests are logged as rows that look the same for a lone request and a lone response; on 151022 Zeek logged 15,734 FC 23 / FC 15 exception responses with no paired request, so those writes never appear as requests. Numbers and causes are in [`samples/README.md`](samples/README.md#zeek-icsnpp-로그로-같은-캡처를-읽으면-2026-11-01).

Numbers, method, and the falsification verdicts are recorded in [`samples/README.md`](samples/README.md).

## Modules

```
pcap/       pcap file → packets. Link layer, IPv4, TCP stream reassembly
decode/     Modbus/TCP · S7comm → Observation   ← protocol knowledge ends here
zeek/       Zeek ICSNPP logs → Observation
contract/   reads CommunicationPolicy
reconcile/  observed ↔ declared → Finding       ← pure logic. No I/O, no protocol knowledge
cli/        entry point and report
```

`pcap`, `decode`, and `reconcile` have no third-party runtime dependencies; only `contract` uses Jackson to read YAML.

**The `decode` boundary was tested, not asserted.** Adding S7comm as a second protocol changed exactly **two files and four lines** outside `decode` — one enum constant and the pipeline's entry-point name — and the 31 existing tests passed without a single edit.

`zeek/` holds log-format knowledge only: headers, which row is a request, which column is the sender. Function-code tables stay in `decode` and are reused, so a request read from a pcap and the same request read from a Zeek log are judged by the same table. `zeek` has no third-party runtime dependency either. Outside `zeek/` and `cli/`, the log path changed one enum constant in `reconcile` (`S7COMM_PLUS`) and, in `decode`, added the `S7PlusAccess` table and one public method, `S7ObjectRef.ofFunction`.

```bash
mvn test
```

313 tests. 7 need the 4SICS captures (`HUGINN_SAMPLES`), 3 need the Zeek logs of those captures (`HUGINN_ZEEK_SAMPLES`), and 2 need the ICSNPP traces (`HUGINN_ICSNPP_TRACES`); without them they are skipped, so a plain `mvn test` executes 301. CI fetches the ICSNPP traces and runs 303.

## What it does not do — and why

| Not done | Why |
|---|---|
| **Live capture** | Permission- and environment-dependent, so tests would not be deterministic. The parser and reconciler are the same either way, so a source adapter can be added later |
| **Active scanning** | In OT a scan can stop equipment. Passive observation is the rule |
| **Automatic blocking or correction** | It **reports and does not fix.** Automatic correction amplifies the damage when the judgment is wrong |
| **Decoding OPC UA · Sparkplug** | Those *are* the governance path, so they are not bypass candidates |
| **Decoding S7comm-plus from pcap** · **Interpreting Userdata (ROSCTR 7)** | S7comm-plus is read from Zeek ICSNPP logs (`--zeek-log`) instead; the 4SICS captures hold zero S7comm-plus frames to verify a decoder against. Userdata is interpreted on neither path — on the log path its requests are `UNDECIDABLE` |
| **Sub-service parsing for S7 control** | The real action of `0x28` lives in a variable-length service string, and a block function's target in a filename-like identifier. With no real capture to check against, parsing them would mean tests validating my own fixtures. They are classified CONTROL wholesale, and **that over-classifies** |
| **Resynchronization after a gap** | Runs after a TCP gap are read only under a strict fit — offset 0 to a clean end. The frame boundary is never *searched for*. A false positive is more expensive than a miss |
| **Per-unit-ID judgment behind a gateway** | The policy is IP-based, so a bypass through a serial gateway is invisible |
| **Absolute performance claims** | Local measurement does not establish them |

## Honest scope & limitations

- **CONTROL is verified synthetically only.** PLC stop and block download are the most important bypass signals in S7, but the 4SICS captures contain none of those eight function codes. The mapping is exercised by fixtures, not by real traffic.
- **Reassembly is the coverage limiter, and this was found the hard way.** Reading only up to the first gap cost 99.9% / 39% / 36% of the observations on the three captures — the report said "2 conversations decoded" while missing nearly all of one. Post-gap runs are now read under a strict fit, and the report carries the bytes never seen. The strict fit is justified by measurement (no run that produced frames ever had leftover bytes), and that fact is guarded as a regression.
- **The captures are one dataset.** 4SICS is S7comm-dominated; Modbus rides on essentially one capture. Three captures do not generalize.
- **Non-standard-port industrial traffic was never seen in real data.** Bypass detection on unusual ports is proven only by synthetic captures.
- **Streams are held in memory**, now including post-gap bytes. A large capture retains hundreds of MB.
- **The log path sees only what Zeek logged.** On the 4SICS captures the logs hold fewer requests than the wire; the report states direction-unknown rows and has no packet or byte coverage to show the rest.
- **`objectRef` is evidence, not judgment.** It says what was touched so an operator can act; it never influences the verdict.
- **The IEC 62443 framing above describes the job, not a certification.** Huginn produces one artefact that 62443 asks an operator to maintain, and it produces it incompletely (see that section). Nothing here has been assessed by anyone.
- Parts were developed with AI assistance; every design decision and every recorded number was verified against real captures and cross-checked with tshark by the author.

Reporting something exploitable: [SECURITY.md](SECURITY.md). Huginn parses attacker-influenced
bytes for a living, so a crafted capture that crashes, hangs, or exhausts memory is in scope; the
limitations listed above are known positions and need not be reported.

Korean README: [README.ko.md](README.ko.md). Design and implementation documents live under [`docs/superpowers/`](docs/superpowers/) — including the falsification conditions each phase set for itself and how they were judged.

## License

[Apache-2.0](LICENSE)
