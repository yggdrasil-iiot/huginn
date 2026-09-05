# Huginn

![Java](https://img.shields.io/badge/Java-17-orange?logo=openjdk&logoColor=white)
![Build](https://img.shields.io/badge/build-Maven%20multi--module-blue)
![Tests](https://img.shields.io/badge/tests-242-brightgreen)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache_2.0-blue.svg)](LICENSE)

**The observation-and-reconciliation arm of the [Yggdrasil](https://github.com/yggdrasil-iiot) IIoT spine — it compares what was *declared* against what actually crossed the wire.** Reads Modbus/TCP and S7comm.

> **Fail-closed only stops what goes through the gate. Huginn sees what didn't.**

[Bifrost](https://github.com/yggdrasil-iiot/bifrost) declares *what may cross the OT/IT boundary*, and a pre-merge gate plus the runtime edge (Heimdall) enforce it. But an engineering workstation wired straight to a PLC, an unregistered device on the segment, a path around the broker — none of those pass through the gate, so nothing knows about them. Huginn reads a pcap, decodes the industrial traffic that actually flowed, and **reconciles it against the declared communication policy** to find undeclared communication.

Commercial OT diagnostic tools must **learn** a baseline from traffic, because nobody declared one. In the Yggdrasil family the **contract is the allowlist** — no signatures, no anomaly model, just comparison.

```
declare (Bifrost) → enforce (gate · Heimdall) → observe (Huginn) → reconcile (Huginn)
   what may            block it at              what actually        difference =
   cross                the gate                 crossed              bypass
```

## Usage

```bash
mvn -DskipTests package
java -jar cli/target/huginn.jar capture.pcap examples/policy.yaml
```

Exit codes: **0** no violations · **1** violations found · **2** usage, input, or contract error. **A large `UNDECIDABLE` count still exits 0 when there are no violations** — coverage is always reported, so the exit code does not have to carry it too.

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

Numbers, method, and the falsification verdicts are recorded in [`samples/README.md`](samples/README.md).

## Modules

```
pcap/       pcap file → packets. Link layer, IPv4, TCP stream reassembly
decode/     Modbus/TCP · S7comm → Observation   ← protocol knowledge ends here
contract/   reads CommunicationPolicy
reconcile/  observed ↔ declared → Finding       ← pure logic. No I/O, no protocol knowledge
cli/        entry point and report
```

`pcap`, `decode`, and `reconcile` have no third-party runtime dependencies; only `contract` uses Jackson to read YAML.

**The `decode` boundary was tested, not asserted.** Adding S7comm as a second protocol changed exactly **two files and four lines** outside `decode` — one enum constant and the pipeline's entry-point name — and the 31 existing tests passed without a single edit.

```bash
mvn test
```

242 tests; 7 of them are regression and diagnostic checks that run only when the 4SICS captures are present (`HUGINN_SAMPLES`). Without the captures they are skipped, so a plain `mvn test` executes 235.

## What it does not do — and why

| Not done | Why |
|---|---|
| **Live capture** | Permission- and environment-dependent, so tests would not be deterministic. The parser and reconciler are the same either way, so a source adapter can be added later |
| **Active scanning** | In OT a scan can stop equipment. Passive observation is the rule |
| **Automatic blocking or correction** | It **reports and does not fix.** Automatic correction amplifies the damage when the judgment is wrong |
| **Decoding OPC UA · Sparkplug** | Those *are* the governance path, so they are not bypass candidates |
| **S7comm-plus** (native S7-1200/1500) · **Userdata (ROSCTR 7)** | Zero frames and four frames respectively across the three captures. No data to verify against |
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
- **`objectRef` is evidence, not judgment.** It says what was touched so an operator can act; it never influences the verdict.
- Parts were developed with AI assistance; every design decision and every recorded number was verified against real captures and cross-checked with tshark by the author.

Korean README: [README.ko.md](README.ko.md). Design and implementation documents live under [`docs/superpowers/`](docs/superpowers/) — including the falsification conditions each phase set for itself and how they were judged.

## License

[Apache-2.0](LICENSE)
