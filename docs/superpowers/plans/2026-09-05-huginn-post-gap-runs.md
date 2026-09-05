# 갭 이후 구간 처리 구현 계획

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 재조립된 TCP 스트림의 갭 이후 구간을 엄격 적합 규칙으로 읽고, 못 본 바이트를 리포트에 낸다.

**Architecture:** `TcpStream` 이 첫 갭까지의 바이트 대신 **구간 목록과 갭 크기**를 낸다. 프레이머는 손대지 않고, 스트림 하나를 읽는 일을 `RunReader` 한 곳으로 모아 여섯 호출부가 같은 수용 규칙을 쓰게 한다. 첫 구간의 처리는 바꾸지 않으므로 갭 없는 스트림은 동작이 그대로다.

**Tech Stack:** Java 17 · Maven 멀티모듈 · JUnit 5 · tshark 4.6.8(검증 오라클) · 4SICS 실캡처 3개

**설계 문서:** [2026-09-05-huginn-post-gap-runs-design.md](../specs/2026-09-05-huginn-post-gap-runs-design.md) (rev3, 승인)

---

## 파일 구조

| 파일 | 책임 | 상태 |
|---|---|---|
| `pcap/…/TcpStream.java` | `runs` · `missingBytes` · 파생 `hasGap()` | 수정 |
| `pcap/…/TcpStreamAssembler.java` | 구간 분할과 구멍 크기 누적 | 수정 |
| `decode/…/Framing.java` | 두 프레이밍 결과의 최소 공통 계약 | 신규 |
| `decode/…/RunReader.java` | **수용 규칙과 스트림 읽기 — 이 설계의 심장** | 신규 |
| `decode/…/FramingResult.java` · `S7FramingResult.java` | `implements Framing` | 수정 |
| `decode/…/ModbusDecoder.java` · `S7Decoder.java` | 여섯 호출부가 `RunReader` 를 쓴다 | 수정 |
| `decode/…/StreamEvidence.java` | `boolean leftoverBytes` → `long unreadBytes` · `long capturedBytes` | 수정 |
| `decode/…/TrafficObserver.java` | 바이트 누적 · 진단 둘 | 수정 |
| `decode/…/ObservationResult.java` · `Diagnosed.java` | 필드 추가 | 수정 |
| `cli/…/Report.java` · `Pipeline.java` | 일곱 번째 줄 | 수정 |
| `decode/src/test/…/RunReaderTest.java` | 수용 규칙 단위 | 신규 |
| `pcap/src/test/…/TcpStreamAssemblerTest.java` | 표현 변경 + **명시된 예외 둘** | 수정 |
| `decode`·`cli` 기존 테스트 | `new TcpStream(...)` 3곳 · `RealCaptureTest` 재작성 | 수정 |

**손대지 않는다:** `ModbusFramer` · `S7Framer` · `ModbusShape` · `ModbusAccess` · `S7Access` · `ModbusObjectRef` · `S7ObjectRef` · `Observation` · `Reconciler` · `contract/` 전체.

---

## Task 0: 기준 커밋

§5 의 회귀 판정과 §6 의 문서 갱신이 이 값에 걸린다.

- [ ] **Step 1: 시작 지점을 기록한다**

```bash
git rev-parse HEAD > .huginn-runs-base
export BASE=$(cat .huginn-runs-base)      # PowerShell: $env:BASE = Get-Content .huginn-runs-base
echo $BASE
```

작업이 끝나면 지운다(Task 10).

- [ ] **Step 2: 지금 상태를 초록으로 확인한다**

Run: `mvn test | grep -E "Tests run:|BUILD"`
Expected: `BUILD SUCCESS`, 총 215건(실캡처 4건은 skip)

---

## Chunk 1: 조립기가 구간을 낸다 — 동작은 아직 그대로다

이 청크가 끝나면 `TcpStream` 은 구간 목록을 내지만 **해독기는 여전히 첫 구간만 읽는다.** 테스트는 표현만 바뀌고 단언 값은 전부 그대로여야 한다. 갭 이후를 실제로 읽는 것은 청크 2다.

### Task 1: `TcpStream` 과 조립기

**Files:**
- Modify: `pcap/src/main/java/dev/krillin/huginn/pcap/TcpStream.java`
- Modify: `pcap/src/main/java/dev/krillin/huginn/pcap/TcpStreamAssembler.java`
- Test: `pcap/src/test/java/dev/krillin/huginn/pcap/TcpStreamAssemblerTest.java`

- [ ] **Step 1: 실패하는 테스트를 쓴다 — 구간 분할과 갭 크기**

`TcpStreamAssemblerTest` 에 두 건을 **새로** 더한다(기존 14건은 Step 3에서 표현만 고친다):

```java
@Test
void 갭_이후_바이트도_구간으로_보존한다() {
    // 지금까지는 갭 이후를 버렸다. 이제 둘째 구간으로 남는다 — 이어붙이지는 않는다.
    List<TcpStream> streams = TcpStreamAssembler.assemble(List.of(
        seg(1000, "abc"), seg(2000, "xyz")));

    TcpStream s = streams.get(0);
    assertEquals(2, s.runs().size());
    assertArrayEquals("abc".getBytes(US_ASCII), s.runs().get(0));
    assertArrayEquals("xyz".getBytes(US_ASCII), s.runs().get(1));
    assertTrue(s.hasGap());
}

@Test
void 구멍의_크기를_센다() {
    // seq 1003 부터 1999 까지 997 바이트가 비었다. 조립기는 이 값을 이미 알면서 버리고 있었다.
    List<TcpStream> streams = TcpStreamAssembler.assemble(List.of(
        seg(1000, "abc"), seg(2000, "xyz")));

    assertEquals(997, streams.get(0).missingBytes());
}

@Test
void 데이터가_없는_스트림은_구간이_없다() {
    // SYN 만 잡힌 방향. runs 는 빈 목록이고 원소로 빈 배열을 넣지 않는다.
    List<TcpStream> streams = TcpStreamAssembler.assemble(List.of(syn(1000)));

    assertTrue(streams.get(0).runs().isEmpty());
    assertEquals(0, streams.get(0).missingBytes());
    assertFalse(streams.get(0).hasGap());
}
```

- [ ] **Step 2: 실패 확인**

Run: `mvn -pl pcap -am test | grep -E "Tests run:|ERROR"`
Expected: 컴파일 실패 — `runs()`·`missingBytes()` 없음

- [ ] **Step 3: `TcpStream` 을 바꾼다**

```java
/**
 * 한 방향의 재조립된 바이트 흐름.
 *
 * @param runs 연속한 바이트 구간들. 구멍을 만나면 끊고 새 구간을 시작한다 — <b>이어붙이지 않는다.</b>
 *             원소는 절대 빈 배열이 아니며, 데이터가 없는 스트림은 <b>빈 목록</b>이다.
 *             <b>주의:</b> {@code byte[]} 를 담으므로 record 의 {@code equals} 는 여전히 참조 비교다.
 * @param missingBytes 구간 사이 구멍들의 크기 합. 캡처가 받지 못한 바이트이며,
 *             "받았지만 해독 못 한" 것과는 다른 값이다(설계 §4)
 * @param truncated  이 방향의 세그먼트 중 하나라도 절단됐으면 true
 * @param sawSynOnly 이 방향에서 SYN 은 서 있고 ACK 는 서 있지 않은 세그먼트를 봤다
 */
public record TcpStream(
    Instant at, String sourceAddress, int sourcePort, String targetAddress, int targetPort,
    List<byte[]> runs, long missingBytes, boolean truncated, boolean sawSynOnly) {

    /** 구간이 둘 이상이면 그 사이에 구멍이 있었다는 뜻이다. */
    public boolean hasGap() {
        return runs.size() > 1;
    }
}
```

- [ ] **Step 4: 조립기의 `compute()` 를 바꾼다**

`Builder` 의 `prefix`·`gap` 필드를 `runs`·`missing` 으로 바꾸고, 갭에서 `break` 하던 것을 **구간을 끊고 계속**하는 것으로 바꾼다:

```java
        private List<byte[]> runs;
        private long missing;
        private boolean computed;

        List<byte[]> runs() { compute(); return runs; }
        long missingBytes() { compute(); return missing; }

        private void compute() {
            if (computed) {
                return;
            }
            computed = true;
            runs = new ArrayList<>();
            missing = 0;
            if (dataSegments.isEmpty()) {
                return;                       // 빈 목록 — 원소로 빈 배열을 넣지 않는다
            }
            // stable sort by seq alone — equal-seq ties keep input order, which is what lets
            // "first wins" resolve a retransmission-disguise deterministically.
            dataSegments.sort(java.util.Comparator.comparingLong(TcpSegment::sequence));

            long nextSeq = dataSegments.get(0).sequence();
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            for (TcpSegment segment : dataSegments) {
                long segStart = segment.sequence();
                long segEnd = segStart + segment.payload().length;
                if (segStart > nextSeq) {
                    // 구멍이다. 이어붙이지 않고 구간을 끊는다 — 크기는 세어 둔다.
                    missing += segStart - nextSeq;
                    if (out.size() > 0) {
                        runs.add(out.toByteArray());
                        out = new ByteArrayOutputStream();
                    }
                    nextSeq = segStart;
                }
                if (segEnd <= nextSeq) {
                    continue;                 // 이미 조립한 바이트에 완전히 덮인다 — first-wins
                }
                int skip = (int) (nextSeq - segStart);
                out.write(segment.payload(), skip, segment.payload().length - skip);
                nextSeq = segEnd;
            }
            if (out.size() > 0) {
                runs.add(out.toByteArray());
            }
        }
```

생성 지점(`assemble` 의 `new TcpStream(...)`)도 새 시그니처에 맞춘다.

- [ ] **Step 5: 기존 14건을 표현만 고친다**

`contiguousPrefix()` → `runs().get(0)`. **단언 값은 하나도 바뀌지 않아야 한다.** 다만 설계 §6이 미리 승인한 **예외 둘**이 있다:

| 테스트 | 바뀌는 것 |
|---|---|
| SYN 만 잡힌 스트림의 `assertEquals(0, s.contiguousPrefix().length)` | `assertTrue(s.runs().isEmpty())` — `runs` 가 빈 목록이라 `get(0)` 이 던진다. 의미는 같다 |
| `갭이_있으면_그_지점부터_UNDECIDABLE이다` | 기존 단언(`runs().get(0)` 이 갭 이전 바이트)은 유지하고, **`runs().get(1)` 이 갭 이후 바이트라는 단언을 더한다.** 조립기 층에서 구간 분할이 고정되는 유일한 자리다 |

그 밖의 테스트에서 단언 값을 고쳐야 한다면 **멈추고 원인을 찾는다** — 표현 변경이 아니라 동작 변경을 한 것이다.

- [ ] **Step 6: 통과 확인**

Run: `mvn -pl pcap -am test | grep -E "Tests run:|BUILD"`
Expected: `TcpStreamAssemblerTest` `Tests run: 17`(기존 14 + 신규 3), 실패 0

- [ ] **Step 7: 커밋**

```bash
git add pcap/src
git commit -m "feat: 조립기가 갭 이후 구간과 구멍 크기를 보존한다"
```

---

### Task 2: 호출부를 컴파일만 되게 맞춘다 — 동작은 그대로

**Files:**
- Modify: `decode/src/main/java/dev/krillin/huginn/decode/ModbusDecoder.java` (3곳)
- Modify: `decode/src/main/java/dev/krillin/huginn/decode/S7Decoder.java` (3곳)
- Modify: `decode/src/test/java/dev/krillin/huginn/decode/ModbusObserverTest.java` · `S7DecoderTest.java` · `CoexistenceTest.java` (`new TcpStream(...)` 헬퍼)

**아직 갭 이후를 읽지 않는다.** 여섯 호출부를 기계적으로 "첫 구간" 으로 바꿔 215건이 그대로 통과하는 상태를 만든다. 이 중간 상태가 있어야 청크 2의 회귀 원인을 좁힐 수 있다.

- [ ] **Step 1: 여섯 호출부를 첫 구간으로 바꾼다**

```java
// 임시 — Task 4 에서 RunReader 로 대체된다.
byte[] firstRun = stream.runs().isEmpty() ? new byte[0] : stream.runs().get(0);
```

`ModbusDecoder` 의 `scan`·관찰 루프·`shapeSignal`, `S7Decoder` 의 `scan`·Job 루프·관찰 루프 여섯 곳이다.

- [ ] **Step 2: 테스트 헬퍼의 생성자를 고친다**

세 파일의 `stream(...)` 헬퍼가 `new TcpStream(at, src, sport, dst, dport, bytes, hasGap, truncated, sawSynOnly)` 를 부른다. 새 시그니처로 바꾼다:

```java
    private static TcpStream stream(String src, int sport, String dst, int dport, byte[] bytes) {
        return new TcpStream(Instant.EPOCH, src, sport, dst, dport,
            bytes.length == 0 ? List.of() : List.of(bytes), 0, false, false);
    }
```

**`ModbusObserverTest` 의 갭 픽스처는 예외다.** 지금 `hasGap = true` 를 배열 하나로 주는데, `hasGap()` 이 `runs.size() > 1` 로 유도되므로 표현이 불가능하다. **둘째 구간에 쓰레기 바이트를 준다** — 청크 2에서 거부되어 `unreadBytes > 0` 이 되고 원래 단언이 그대로 성립한다:

```java
    // 갭이 있는 스트림 — 둘째 구간은 프레임이 되지 않는 바이트다(청크 2에서 거부된다).
    private static TcpStream gappedStream(String src, int sport, String dst, int dport, byte[] bytes) {
        return new TcpStream(Instant.EPOCH, src, sport, dst, dport,
            List.of(bytes, "쓰레기".getBytes(UTF_8)), 100, false, false);
    }
```

- [ ] **Step 3: 통과 확인**

Run: `mvn test | grep -E "Tests run:|BUILD"`
Expected: `BUILD SUCCESS`, 215건 그대로. **단언 값이 하나도 바뀌지 않았다.**

Run: `git diff HEAD --stat -- decode/src/test cli/src/test`
Expected: 세 테스트 파일의 헬퍼만 바뀐다. 다른 테스트가 바뀌었다면 멈춘다.

- [ ] **Step 4: 커밋**

```bash
git add decode/src
git commit -m "refactor: 호출부를 첫 구간으로 맞춘다 — 동작 변경 없음"
```

---

## Chunk 2: 엄격 적합으로 갭 이후를 읽는다

### Task 3: `Framing` 인터페이스

**Files:**
- Create: `decode/src/main/java/dev/krillin/huginn/decode/Framing.java`
- Modify: `decode/src/main/java/dev/krillin/huginn/decode/FramingResult.java` · `S7FramingResult.java`

- [ ] **Step 1: 인터페이스와 구현**

```java
package dev.krillin.huginn.decode;

/**
 * 수용 정책이 프로토콜을 몰라도 되게 하는 최소 계약.
 *
 * <p>딱 두 메서드다. 프로토콜 고유의 것(프레임 목록·COTP 분할 여부)은 호출자가 구체 타입에서
 * 그대로 꺼내 쓴다 — 여기로 끌어올리면 이음매가 프로토콜을 알게 된다.
 */
interface Framing {
    int frameCount();
    int leftoverBytes();
}
```

```java
public record FramingResult(List<ModbusFrame> frames, int undecodedBytes, boolean isModbusStream)
        implements Framing {
    @Override public int frameCount() { return frames.size(); }
    @Override public int leftoverBytes() { return undecodedBytes; }
}
```

`S7FramingResult` 도 같은 방식으로(`frames.size()` · `undecodedBytes`).

- [ ] **Step 2: 컴파일 확인**

Run: `mvn -pl decode -am test-compile`
Expected: 성공

- [ ] **Step 3: 커밋**

```bash
git add decode/src/main
git commit -m "feat: 두 프레이밍 결과의 최소 공통 계약"
```

---

### Task 4: `RunReader` — 이 설계의 심장

**Files:**
- Create: `decode/src/main/java/dev/krillin/huginn/decode/RunReader.java`
- Test: `decode/src/test/java/dev/krillin/huginn/decode/RunReaderTest.java`

- [ ] **Step 1: 실패하는 테스트를 쓴다**

```java
class RunReaderTest {

    private static TcpStream withRuns(long missing, byte[]... runs) {
        return new TcpStream(Instant.EPOCH, "10.0.0.1", 1000, "10.0.0.2", 502,
            List.of(runs), missing, false, false);
    }

    @Test
    void 첫_구간은_조건_없이_받는다() {
        // 지금 동작 그대로다 — 잔여가 남아도 받는다. 이 성질이 갭 없는 스트림의 동작을 보존한다.
        byte[] withGarbage = ModbusFixtures.concat(
            ModbusFixtures.mbap(1, 1, 3, ModbusFixtures.pdu(0, 2)),
            "GET / HTTP/1.1\r\n".getBytes(US_ASCII));

        var reading = RunReader.read(withRuns(0, withGarbage), ModbusFramer::frames);

        assertEquals(1, reading.accepted().size());
        assertEquals(16, reading.unreadBytes(), "첫 구간의 잔여는 그대로 센다");
        assertEquals(0, reading.rejectedRuns());
    }

    @Test
    void 이후_구간은_잔여가_0일_때만_받는다() {
        byte[] clean = ModbusFixtures.mbap(1, 1, 3, ModbusFixtures.pdu(0, 2));
        byte[] dirty = ModbusFixtures.concat(clean, new byte[]{0x01, 0x02, 0x03});

        var accepted = RunReader.read(withRuns(50, clean, clean), ModbusFramer::frames);
        assertEquals(2, accepted.accepted().size());
        assertEquals(0, accepted.unreadBytes());
        assertEquals(0, accepted.rejectedRuns());

        var rejected = RunReader.read(withRuns(50, clean, dirty), ModbusFramer::frames);
        assertEquals(1, rejected.accepted().size(), "지저분한 구간은 통째로 버린다");
        assertEquals(dirty.length, rejected.unreadBytes(), "잔여만 세면 버린 양을 축소 보고한다");
        assertEquals(1, rejected.rejectedRuns());
        assertEquals(1, rejected.dirtyRuns(), "프레임이 나왔는데 버린 구간이다 — 설계 §7 의 반증 지표");
    }

    @Test
    void 프레임이_하나도_없는_이후_구간은_거부한다() {
        byte[] clean = ModbusFixtures.mbap(1, 1, 3, ModbusFixtures.pdu(0, 2));
        byte[] garbage = "SSH-2.0-OpenSSH_9.0\r\n".getBytes(US_ASCII);

        var reading = RunReader.read(withRuns(50, clean, garbage), ModbusFramer::frames);

        assertEquals(1, reading.accepted().size());
        assertEquals(garbage.length, reading.unreadBytes());
        assertEquals(1, reading.rejectedRuns());
        assertEquals(0, reading.dirtyRuns(), "프레임이 없었으므로 지저분한 구간이 아니다");
    }

    @Test
    void 연결_설정만_든_구간은_미해독_바이트가_아니다() {
        // 2차가 못박은 원칙 — 비-S7 TPKT 는 미해독이 아니다. 구간 길이를 통째로 세면 그게 깨진다.
        byte[] job = S7Fixtures.job(S7Fixtures.readVar(S7Fixtures.sym(0, 0x52, 16)));

        var reading = RunReader.read(
            withRuns(50, job, S7Fixtures.connectRequest()), S7Framer::frames);

        assertEquals(1, reading.accepted().size());
        assertEquals(0, reading.unreadBytes(), "버려졌지만 미해독 바이트는 아니다");
        assertEquals(1, reading.rejectedRuns(), "버려진 사실은 진단에 남는다");
    }

    @Test
    void 구간이_없으면_전부_0이다() {
        var reading = RunReader.read(withRuns(0), ModbusFramer::frames);

        assertTrue(reading.accepted().isEmpty());
        assertEquals(0, reading.unreadBytes());
        assertEquals(0, reading.capturedBytes());
    }

    @Test
    void 받은_바이트를_전부_센다() {
        byte[] clean = ModbusFixtures.mbap(1, 1, 3, ModbusFixtures.pdu(0, 2));

        var reading = RunReader.read(withRuns(997, clean, clean), ModbusFramer::frames);

        assertEquals(clean.length * 2L, reading.capturedBytes(), "구멍은 여기 안 든다 — missingBytes 가 따로 센다");
    }
}
```

- [ ] **Step 2: 실패 확인**

Run: `mvn -pl decode -am test | grep -cE "ERROR.*cannot find symbol"`
Expected: 0 이 아닌 수

- [ ] **Step 3: 구현**

```java
package dev.krillin.huginn.decode;

import dev.krillin.huginn.pcap.TcpStream;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;

/**
 * 스트림의 구간들을 프레이밍하고 <b>수용된 것만</b> 낸다.
 *
 * <p><b>수용 규칙이 이 클래스의 전부이고, 그 한 줄이 1차 원칙과의 경계선이다.</b> 첫 구간은
 * 조건 없이 받고, 이후 구간은 프레임이 하나 이상이고 잔여가 0 일 때만 받는다.
 *
 * <p>경계를 <b>찾지</b> 않으므로 1차가 거부한 재동기화가 아니다 — 각 구간의 오프셋 0 하나만
 * 시도하고 끝까지 정확히 떨어질 때만 받는다. 중간부터 시작한 구간은 거의 확실히 걸러진다.
 * 실캡처 세 개에서 프레임이 나온 갭 이후 구간은 전부 잔여 0 이었다(설계 §1).
 *
 * <p>여섯 호출부가 전부 이것을 부른다. 각자 규칙을 적용하면 방향 판정이 자기 증거와 어긋난다 —
 * {@code scan} 이 거부한 구간의 프레임을 {@code shapeSignal} 이 보는 식이다.
 */
final class RunReader {

    private RunReader() {
    }

    static <F extends Framing> Reading<F> read(TcpStream stream, Function<byte[], F> framer) {
        List<F> accepted = new ArrayList<>();
        long unread = 0;
        long captured = 0;
        int rejected = 0;
        int dirty = 0;

        List<byte[]> runs = stream.runs();
        for (int i = 0; i < runs.size(); i++) {
            byte[] run = runs.get(i);
            captured += run.length;
            F framing = framer.apply(run);

            if (i == 0) {
                accepted.add(framing);
                unread += framing.leftoverBytes();     // 첫 구간은 지금 동작 그대로
                continue;
            }
            if (framing.frameCount() > 0 && framing.leftoverBytes() == 0) {
                accepted.add(framing);
                continue;
            }

            rejected++;
            if (framing.frameCount() > 0) {
                dirty++;
                unread += run.length;      // 읽을 수 있었으나 믿지 못해 통째로 버렸다
            } else {
                // 프레임이 없다. 잔여만 센다 — 연결 설정만 든 구간은 0 이 되며, 그것이
                // 2차의 "비-S7 TPKT 는 미해독 바이트가 아니다" 원칙이다.
                unread += framing.leftoverBytes();
            }
        }

        return new Reading<>(List.copyOf(accepted), unread, captured, rejected, dirty);
    }

    /**
     * @param accepted      수용된 구간의 프레이밍 결과(구간 순서). 프로토콜 고유 정보는
     *                      호출자가 구체 타입에서 꺼낸다
     * @param unreadBytes   받았지만 프레임이 덮지 못한 바이트
     * @param capturedBytes 이 스트림에서 실제로 받은 바이트. <b>구멍은 여기 들지 않는다</b>
     * @param rejectedRuns  거부한 구간 수
     * @param dirtyRuns     그중 프레임이 나왔던 구간 수 — 0 이어야 한다(설계 §7)
     */
    record Reading<F>(List<F> accepted, long unreadBytes, long capturedBytes,
                      int rejectedRuns, int dirtyRuns) {
    }
}
```

- [ ] **Step 4: 통과 확인**

Run: `mvn -pl decode -am test | grep -E "RunReaderTest|BUILD"`
Expected: `Tests run: 6, Failures: 0`

- [ ] **Step 5: 커밋**

```bash
git add decode/src
git commit -m "feat: 엄격 적합 수용 — 경계를 찾지 않으므로 재동기화가 아니다"
```

---

### Task 5: 두 해독기가 `RunReader` 를 쓴다

**Files:**
- Modify: `decode/src/main/java/dev/krillin/huginn/decode/StreamEvidence.java`
- Modify: `decode/src/main/java/dev/krillin/huginn/decode/ModbusDecoder.java` · `S7Decoder.java`

- [ ] **Step 1: `StreamEvidence` 를 바꾼다**

```java
/**
 * @param frameCount    수용된 구간들에서 나온 프레임 수. 0 이면 이 스트림은 이 프로토콜이 아니다
 * @param unreadBytes   받았지만 프레임이 덮지 못한 바이트(설계 §3 의 구간별 계산표)
 * @param capturedBytes 이 스트림에서 실제로 받은 바이트. 구멍은 {@code stream.missingBytes()} 가 센다
 */
record StreamEvidence(TcpStream stream, int frameCount, long unreadBytes, long capturedBytes) {
}
```

- [ ] **Step 2: `ModbusDecoder` 의 세 곳을 바꾼다**

`scan` 은 `RunReader` 로 증거를 만들고, 관찰 루프와 `shapeSignal` 은 **수용된 구간들의 프레임을 이어 붙인 목록**을 본다:

```java
    @Override
    public StreamEvidence scan(TcpStream stream) {
        var reading = RunReader.read(stream, ModbusFramer::frames);
        return new StreamEvidence(stream, framesOf(reading).size(),
            reading.unreadBytes(), reading.capturedBytes());
    }

    /** 수용된 구간들의 프레임을 순서대로 이어 붙인다 — 구간별로 따로 판정하지 않는다. */
    private static List<ModbusFrame> framesOf(RunReader.Reading<FramingResult> reading) {
        List<ModbusFrame> frames = new ArrayList<>();
        for (FramingResult one : reading.accepted()) {
            frames.addAll(one.frames());
        }
        return frames;
    }
```

`shapeSignal` 은 `ModbusShape.ofStream(framesOf(RunReader.read(...)))` 를, 관찰 루프는 같은 목록을 돈다.

> **왜 이어 붙이나.** 두 구간의 형태가 어긋나면 합쳐서 `UNKNOWN` 이 되고, 그것은 판정 불가 쪽으로 기우는 보수적 방향이라 이 설계의 원칙과 맞다(설계 §3).

- [ ] **Step 3: `S7Decoder` 의 세 곳을 바꾼다**

같은 방식이다. Job 루프의 `unread |= framing.fragmented()` 는 **거부된 구간의 분할도 포함**한다(설계 §3) — `RunReader.Reading` 은 수용된 것만 주므로, `fragmented` 는 구간 전체를 다시 훑어 판정한다:

```java
        boolean unread = false;
        for (byte[] run : evidence.stream().runs()) {
            unread |= S7Framer.frames(run).fragmented();     // 수용 여부와 무관한 스트림의 사실
        }
```

- [ ] **Step 4: 통과 확인**

Run: `mvn test | grep -E "Tests run:|BUILD|FAIL"`
Expected: `BUILD SUCCESS`. **`ModbusObserverTest.갭이_있는_스트림은…` 이 여기서 진짜 시험된다** — 둘째 구간의 쓰레기가 거부되어 `unreadBytes > 0` 이 되고 원래 단언이 성립해야 한다.

`RealCaptureTest` 는 아직 옛 기대값이라 실캡처를 물리면 실패한다. Task 8에서 다시 잡는다.

- [ ] **Step 5: 커밋**

```bash
git add decode/src
git commit -m "feat: 여섯 호출부가 같은 수용 규칙을 쓴다"
```

---

### Task 6: 순회기가 바이트를 센다

**Files:**
- Modify: `decode/src/main/java/dev/krillin/huginn/decode/ObservationResult.java` · `Diagnosed.java` · `TrafficObserver.java`
- Test: `decode/src/test/java/dev/krillin/huginn/decode/CoexistenceTest.java` (새 테스트 한 건)

- [ ] **Step 1: 실패하는 테스트를 쓴다**

```java
@Test
void 산업_대화의_못_본_바이트를_센다() {
    // 분자 = 미해독 + 구멍, 분모 = 받은 것 + 구멍. 대상 외 대화는 양쪽 어디에도 안 든다.
    byte[] frame = ModbusFixtures.mbap(1, 1, 3, ModbusFixtures.pdu(0, 2));
    TcpStream gapped = new TcpStream(Instant.EPOCH, "10.0.1.20", 40000, "10.0.2.11", 502,
        List.of(frame), 500, false, false);          // 구멍 500 바이트
    TcpStream ssh = stream("10.0.1.20", 40002, "10.0.3.5", 22,
        "SSH-2.0-OpenSSH_9.0\r\n".getBytes(US_ASCII));

    ObservationResult r = TrafficObserver.observe(List.of(gapped, ssh));

    assertEquals(500, r.unobservedBytes(), "구멍은 못 본 바이트다");
    assertEquals(frame.length + 500, r.industrialBytes(), "SSH 대화는 분모에도 안 든다");
}
```

- [ ] **Step 2: 실패 확인** → `unobservedBytes` 없음

- [ ] **Step 3: 필드를 더한다**

```java
/**
 * @param unobservedBytes 산업 대화에서 <b>보지 못한</b> 바이트 — 받았지만 해독 못 한 것 + 캡처에 없던 것.
 *                        받지 못한 것은 "미해독" 이 아니지만 <b>못 본 것은 맞다</b>
 * @param industrialBytes 그 대화들이 실제로 오갔던 바이트(받은 것 + 캡처에 없던 것)
 */
public record ObservationResult(List<Observation> observations,
                                int decodedConversations, int undecidableConversations,
                                int skippedConversations,
                                long unobservedBytes, long industrialBytes) { }
```

`Diagnosed` 에는 `rejectedRuns`·`dirtyRuns` 를 더한다.

- [ ] **Step 4: 순회기에서 누적한다**

대상 외로 빠져나가는 `continue` **뒤에서** 센다 — 배제가 규칙이 아니라 구조로 지켜진다:

```java
            // (claimers.isEmpty() → skipped++; continue; 이후)
            for (StreamEvidence one : conversationEvidence) {
                unobserved += one.unreadBytes() + one.stream().missingBytes();
                industrial += one.capturedBytes() + one.stream().missingBytes();
            }
```

`rejectedRuns`·`dirtyRuns` 는 이긴 해독기의 `scan` 이 이미 센 값을 쓰려면 `StreamEvidence` 에 실어야 하므로, **진단 전용으로 `RunReader` 를 한 번 더 돌리지 말고** `StreamEvidence` 에 두 필드를 더해 나른다.

- [ ] **Step 5: 통과 확인**

Run: `mvn test | grep -E "Tests run:|BUILD"`
Expected: `BUILD SUCCESS`

- [ ] **Step 6: 커밋**

```bash
git add decode/src
git commit -m "feat: 산업 대화의 못 본 바이트를 센다"
```

---

## Chunk 3: 리포트와 실캡처 판정

### Task 7: 리포트의 일곱 번째 줄

**Files:**
- Modify: `cli/src/main/java/dev/krillin/huginn/cli/Report.java` · `Pipeline.java`
- Test: `cli/src/test/java/dev/krillin/huginn/cli/EndToEndTest.java` (새 테스트 한 건)

- [ ] **Step 1: 실패하는 테스트**

```java
@Test
void 리포트는_못_본_바이트를_비율과_함께_낸다() {
    // 이 줄이 없으면 "해독한 대화 2" 가 그 대화의 99.99% 를 못 봤다는 사실을 숨긴다.
    String out = Pipeline.run(declaredReadCapture(), POLICY).render();

    assertTrue(out.contains("미관측 바이트"));
    assertTrue(out.matches("(?s).*미관측 바이트.*\\(\\d+\\.\\d%\\).*"), "비율은 소수 한 자리다");
}
```

- [ ] **Step 2: 실패 확인** → 그 줄이 없다

- [ ] **Step 3: `Report` 를 바꾼다**

컴포넌트 둘을 더하고, `count(String, int)` 를 `long` 도 받게 확장하고, 비율 판을 새로 만든다:

```java
    /** 비율은 소수 한 자리다 — 정수로 자르면 0.4% 가 0% 가 되어 실제 손실을 숨긴다. */
    private static String countWithRatio(String label, long value, long total) {
        String amount = String.format(Locale.ROOT, "%,d (%.1f%%)",
            value, total == 0 ? 0.0 : 100.0 * value / total);
        int padding = Math.max(1, LABEL_WIDTH - displayWidth(label));
        return "  " + label + " ".repeat(padding) + String.format(Locale.ROOT, "%16s", amount) + "\n";
    }
```

`render()` 의 여섯 줄 뒤에 `countWithRatio("미관측 바이트", unobservedBytes, industrialBytes)` 를 더한다. `Pipeline` 은 새 필드를 넘긴다.

- [ ] **Step 4: 통과 확인**

Run: `mvn test | grep -E "Tests run:|BUILD"`
Expected: `BUILD SUCCESS`, `cli` 12건

- [ ] **Step 5: 커밋**

```bash
git add cli/src
git commit -m "feat: 리포트가 못 본 바이트를 낸다"
```

---

### Task 8: 실캡처 재측정과 `RealCaptureTest` 재작성

**Files:**
- Modify: `decode/src/test/java/dev/krillin/huginn/decode/RealCaptureTest.java`

**이 설계가 깨뜨리려고 만든 테스트다.** 옛 기대값 `21 / 52,607 / 34,154` 는 "첫 갭까지만 읽는다" 는 정책의 산물이었다.

- [ ] **Step 1: 새 수치를 측정한다**

```powershell
$env:HUGINN_SAMPLES = "C:/path/to/huginn/samples"   # 절대 경로 — surefire 작업 디렉터리는 모듈 basedir 다
mvn -pl decode -am test -Dtest=RealCaptureTest -Dsurefire.failIfNoSpecifiedTests=false
```

`수치를_기록한다` 가 찍는 값을 받아 적는다. **`dirtyRuns` 가 0 인지 먼저 본다** — 0 이 아니면 설계 §7 의 반증 조건이 발동한 것이고, 수치를 적기 전에 그것부터 다룬다.

- [ ] **Step 2: 테스트를 다시 쓴다**

- 이름을 `S7_프레임_관찰_수는_첫_갭까지의_커버리지와_같다` → `S7_프레임_관찰_수가_tshark_Job_수에_근접한다` 로
- 15줄 주석을 새 정책으로 교체(옛 커버리지 설명은 이제 틀렸다)
- 기대값을 측정값으로. **tshark Job 수(23,732 / 86,403 / 53,217)와의 남은 차이는 반드시 설명한다** — 남는 원인은 양방향 요청 대화와 거부된 구간뿐이다
- `dirtyRuns == 0` 과 `rejectedRuns` 기록을 단언·출력으로 추가
- **Modbus 기준선**(해독 56 · 대상 외 932,655 · UNDECIDABLE 대화 24 · 관찰 48 · 총 49,767)이 움직이면 새 값으로 잡고 **왜 움직였는지 주석에 적는다**

- [ ] **Step 3: 통과 확인**

Run: 위 명령
Expected: 4건 통과

- [ ] **Step 4: 커밋**

```bash
git add decode/src/test
git commit -m "test: 갭 이후를 읽는 정책의 실캡처 수치를 다시 잡는다"
```

---

### Task 9: 샘플 결과와 문서

**Files:**
- Modify: `samples/README.md` · `README.md`
- Modify: `docs/superpowers/specs/2026-09-05-huginn-design.md` (§5-③ · §10)
- Modify: `docs/superpowers/specs/2026-09-05-huginn-s7comm-design.md` (§9 판정표)

- [ ] **Step 1: CLI 를 다시 돌려 결과표를 얻는다**

```bash
mvn -q -DskipTests package
chcp 65001
for f in 151020 151021 151022; do
  java -Dstdout.encoding=UTF-8 -jar cli/target/huginn.jar \
       samples/4SICS-GeekLounge-$f.pcap samples/4SICS-GeekLounge-$f-policy.yaml
done
```

- [ ] **Step 2: `samples/README.md` 를 갱신한다**

- 결과표에 **미관측 바이트 열** 추가, 여섯 수치 재기록
- §④ 를 다시 쓴다 — 발견을 지우지 않고 **"발견 → 해소" 로 잇는다.** 무엇을 얼마나 되찾았는지, 남은 손실은 무엇인지
- **인용 정정**: *"소수점 둘째 자리까지 일치"* → 설계 §1 의 정확한 표현으로(151020 은 0.01% 대 0.09% 로 9배 차이다)
- 아직 검증되지 않은 것 목록 갱신

- [ ] **Step 3: 원칙을 적어둔 문서를 갱신한다**

| 문서 | 고칠 것 |
|---|---|
| `README.md:47` | "커버리지 **여섯 수치**" → 일곱 |
| `README.md` 예시 리포트 블록 | 일곱 번째 줄 추가 |
| `README.md` "하지 않는 것" 표 | *"갭 이후 구간 해독 … 지금 동작은 의도된 것"* 행 제거 또는 "엄격 적합으로 읽는다" 로 교체 |
| 1차 §5-③ | *"그 지점부터 `UNDECIDABLE`"* → 이어붙이지 않고 **따로 읽는다** 로 갱신. 원칙(이어붙이지 않는다)은 유지 |
| 1차 §10 | 인용 정정 + 이 작업으로 한계가 해소됐음을 추가 |
| 2차 §9 판정표 | "커버리지와 소수점 둘째 자리까지 일치" 문장 정정 |

- [ ] **Step 4: 전체 검증**

```bash
rm .huginn-runs-base
```

Run: `mvn test | grep -E "Tests run:|BUILD"`
Expected: `BUILD SUCCESS`

Run: `git status -sb`
Expected: 워킹트리 깨끗

- [ ] **Step 5: 커밋**

```bash
git add -A
git commit -m "docs: 갭 이후 구간 처리 결과와 인용 정정"
```

---

## 완료 조건

- [ ] `mvn test` 전체 통과
- [ ] **갭 없는 스트림만으로 이뤄진 대화의 판정이 하나도 움직이지 않았다** — `ModbusObserverTest` 20건과 `cli` 기존 11건의 단언 값이 그대로다(헬퍼 시그니처 변경은 표현)
- [ ] `pcap` 14건이 표현만 바뀌었다 — **명시된 예외 둘** 외에 단언 값이 바뀌지 않았다
- [ ] **`dirtyRuns` 가 세 캡처 모두 0 이다** — 설계 §7 의 첫 반증 조건
- [ ] **대상 외 대화 수가 크게 줄지 않았다**(`932,647 / 112,730 / 7,288` 기준) — 줄었다면 비산업 트래픽이 엄격 적합을 통과한 것이고, 그것이 오탐이다
- [ ] S7 관찰 수가 tshark Job 수에 근접하고, **남은 차이를 원인별로 설명했다**
- [ ] Modbus 기준선이 움직였다면 **왜 움직였는지 적었다**
- [ ] 리포트가 일곱 줄이고 미관측 바이트가 비율과 함께 나온다
- [ ] `ModbusFramer`·`S7Framer`·`ModbusShape` 가 한 줄도 바뀌지 않았다
      Run: `git diff --stat $BASE..HEAD -- decode/src/main/java/dev/krillin/huginn/decode/ModbusFramer.java decode/src/main/java/dev/krillin/huginn/decode/S7Framer.java decode/src/main/java/dev/krillin/huginn/decode/ModbusShape.java` → Expected: 빈 출력
- [ ] 옛 정책을 원칙으로 적어둔 문서 여섯 곳이 전부 갱신됐다
- [ ] **인용 오류가 세 문서에서 정정됐다** — "소수점 둘째 자리까지 일치"
