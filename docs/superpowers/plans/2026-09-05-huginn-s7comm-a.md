# Huginn 2차 A단계 — S7comm Read/Write와 이음매 구현 계획

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `decode` 안을 프로토콜 중립 순회기와 `ProtocolDecoder` 이음매로 가르고, 그 뒤에 S7comm Read/Write 해독기를 붙여 1차 §10의 이음매 반증 조건을 판정한다.

**Architecture:** 지금 `ModbusObserver` 하나에 섞여 있는 "대화 순회·계수"와 "Modbus 판정"을 가른다. 앞은 `TrafficObserver`가 되고 뒤는 `ModbusDecoder`가 된다. `S7Decoder`는 같은 인터페이스 뒤에 들어가며, S7은 ROSCTR 필드가 요청/응답을 선언하므로 Modbus의 S1·S2·R1~R5 기계가 필요 없다. `ObservationResult`와 리포트는 건드리지 않는다 — 그것이 이음매 판정의 조건이다.

**Tech Stack:** Java 17 · Maven 멀티모듈 · JUnit 5 · tshark 4.6.8(검증 오라클) · 4SICS ICS Lab 캡처 3개

**설계 문서:** [2026-09-05-huginn-s7comm-design.md](../specs/2026-09-05-huginn-s7comm-design.md) (rev6, 승인)

---

## 파일 구조

| 파일 | 책임 | 상태 |
|---|---|---|
| `decode/…/ProtocolDecoder.java` | 이음매 인터페이스 | 신규 |
| `decode/…/StreamEvidence.java` | 스트림 하나의 프레임 증거 | 신규 |
| `decode/…/Decoded.java` | 해독기가 낸 관찰과 방향 판정 | 신규 |
| `decode/…/TrafficObserver.java` | 대화 순회·계수. 프로토콜을 모른다 | 신규 |
| `decode/…/Diagnosed.java` | 테스트 전용 진단 묶음 | 신규 |
| `decode/…/ModbusDecoder.java` | 1차 판정 로직을 인터페이스 뒤로 감싼다 | 신규 |
| `decode/…/ModbusObserver.java` | Modbus 전용 진입점으로 축소(위임) | 수정 |
| `decode/…/S7Frame.java` | S7 프레임 하나 | 신규 |
| `decode/…/S7FramingResult.java` | 프레이밍 결과 | 신규 |
| `decode/…/S7Framer.java` | TPKT→COTP→S7 3중 프레이밍 | 신규 |
| `decode/…/S7Access.java` | 함수코드 → Access | 신규 |
| `decode/…/S7ObjectRef.java` | 1200SYM·S7ANY 주소 표기 | 신규 |
| `decode/…/S7Decoder.java` | ROSCTR 방향 판정과 관찰 생성 | 신규 |
| `decode/src/test/…/S7Fixtures.java` | S7 바이트 픽스처(`public`) | 신규 |
| `cli/…/Pipeline.java` | 진입점 배선 — **§7 예산 3줄** | 수정 |
| `reconcile/…/Protocol.java` | `S7COMM` 상수 하나 — **§7 예산** | 수정 |
| `samples/*-policy.yaml` (3개) | S7 규칙 추가 | 수정 |
| `samples/README.md` | 결과표 재기록 | 수정 |
| `decode/src/test/…/S7FixturesTest.java` | 픽스처가 실캡처 바이트를 재현하는지 | 신규 |
| `decode/src/test/…/S7FramerTest.java` · `S7AccessTest` · `S7ObjectRefTest` · `S7DecoderTest` | 각 단위 | 신규 |
| `decode/src/test/…/CoexistenceTest.java` | 두 프로토콜 공존과 프레이머 배타성 | 신규 |
| `decode/src/test/…/RealCaptureTest.java` | 실캡처 회귀·진단(환경변수 게이트) | 신규 |

**손대지 않는다:** `ObservationResult` · `Report` · `Huginn` · `contract/` 전체 · `pcap/` 전체 · `ModbusFramer`·`ModbusShape`·`ModbusAccess`·`ModbusObjectRef` · `ModbusObserverTest` · `EndToEndTest` · `ExamplePolicyTest`.

---

## Chunk 1: 이음매 추출 — 동작은 한 톨도 바뀌지 않는다

이 청크의 검증은 단순하다. **`ModbusObserverTest` 20건과 `cli` 11건이 한 줄도 고쳐지지 않은 채 그대로 통과하면 성공이고, 하나라도 고쳐야 하면 실패다.** 새 테스트를 쓰지 않는다 — 기존 테스트가 그물이다.

### Task 0: 기준 커밋을 잡는다

§7의 이음매 측정이 전부 이 값에 걸린다. 잡아두지 않으면 Task 3·12와 완료 조건의 명령이 실행 불가능하다.

- [x] **Step 1: 시작 지점을 기록한다**

```bash
git rev-parse HEAD > .huginn-a-base    # .gitignore 에 넣지 않는다 — 커밋하지 말고 로컬에만 둔다
export BASE=$(cat .huginn-a-base)      # PowerShell: $env:BASE = Get-Content .huginn-a-base
echo $BASE
```

이후 계획서의 `$BASE` 는 전부 이 값이다. 작업이 끝나면 이 파일을 지운다.

---

### Task 1: 이음매 타입 셋

**Files:**
- Create: `decode/src/main/java/dev/krillin/huginn/decode/StreamEvidence.java`
- Create: `decode/src/main/java/dev/krillin/huginn/decode/Decoded.java`
- Create: `decode/src/main/java/dev/krillin/huginn/decode/ProtocolDecoder.java`

타입만 만든다. 소비자가 없으므로 테스트도 없다 — Task 2가 첫 소비자이고 그때 기존 20건이 검증한다.

- [x] **Step 1: `StreamEvidence` 작성**

```java
package dev.krillin.huginn.decode;

import dev.krillin.huginn.pcap.TcpStream;

/**
 * 스트림 하나에 대한 한 프로토콜의 증거.
 *
 * <p>프레임 자체를 노출하지 않는 것이 요점이다. 순회기는 개수와 잔여 여부, 그리고
 * {@link TcpStream} 의 {@code hasGap}·{@code truncated} 만 보고, 프레임·함수코드·PDU 형태는
 * 해독기 밖으로 나오지 않는다.
 *
 * @param frameCount    이 프로토콜의 유효 프레임 수. 0 이면 이 스트림은 이 프로토콜이 아니다
 * @param leftoverBytes 프레임 뒤에 해독하지 못한 바이트가 남았는가
 */
record StreamEvidence(TcpStream stream, int frameCount, boolean leftoverBytes) {
}
```

- [x] **Step 2: `Decoded` 작성**

```java
package dev.krillin.huginn.decode;

import dev.krillin.huginn.reconcile.Observation;

import java.util.List;

/**
 * 해독기가 대화 하나를 읽은 결과.
 *
 * @param requestObservations 요청 프레임에서 만든 관찰. 응답은 들어가지 않는다(1차 설계 §5-⑤)
 * @param client              요청을 보낸 방향의 증거. <b>null 이면 판정 불가</b>다.
 *                            {@link TcpStream} 이 아니라 증거를 돌려주는 이유 — TcpStream 은
 *                            {@code byte[]} 컴포넌트를 가진 record 라 equals 가 배열 참조 비교다.
 *                            되짚으려 하면 동일 인스턴스일 때만 우연히 동작한다
 * @param tailUndecidable     프레임은 뽑았으나 해석하지 않은 것이 대화 어딘가에 있는가.
 *                            S7 이 Userdata(ROSCTR 7)나 COTP 분할을 만났을 때 세운다 — 그것들은
 *                            응답 방향에도 실리므로 client 의 잔여만 보는 규칙으로는 잡히지 않는다.
 *                            Modbus 는 항상 false 다
 * @param bothDirectionsRequested client == null 인 이유가 <b>요청 방향이 둘</b>이어서인가.
 *                            요청 방향 0 개(응답만 잡힘)와 2 개를 순회기는 구별할 수 없다 —
 *                            둘 다 frameCount > 0 이기 때문이다. 해독기만 아는 사실이다
 */
record Decoded(List<Observation> requestObservations,
               StreamEvidence client,
               boolean tailUndecidable,
               boolean bothDirectionsRequested) {

    static Decoded undecided(boolean bothDirectionsRequested) {
        return new Decoded(List.of(), null, false, bothDirectionsRequested);
    }
}
```

- [x] **Step 3: `ProtocolDecoder` 작성**

```java
package dev.krillin.huginn.decode;

import dev.krillin.huginn.pcap.TcpStream;
import dev.krillin.huginn.reconcile.Protocol;

import java.util.List;

/**
 * 이음매. <b>프로토콜 지식은 전부 이 뒤에 있다.</b>
 *
 * <p>1차 설계 §10 의 반증 조건이 이 인터페이스를 겨냥한다 — 두 번째 프로토콜을 붙일 때
 * {@code decode} 밖이 바뀌어야 하면 {@code Observation} 이음매를 잘못 잡은 것이다.
 */
interface ProtocolDecoder {

    Protocol protocol();

    /** 이 스트림에서 이 프로토콜의 프레임이 몇 개 나오는가. */
    StreamEvidence scan(TcpStream stream);

    /**
     * 대화에서 요청 관찰을 만든다. 방향 판정 방식은 프로토콜마다 다르므로 여기 안에 있다.
     *
     * @param conversation 이 대화의 <b>모든</b> 스트림. {@code frameCount == 0} 인 것도 빼지 않는다 —
     *                     Modbus 의 R5(고른 방향이 캡처에 없음) 판정이 그 부재를 봐야 성립한다.
     *                     순서는 입력 목록에 처음 등장한 순서다.
     */
    Decoded decode(List<StreamEvidence> conversation);
}
```

- [x] **Step 4: 컴파일 확인**

Run: `mvn -pl decode -am test-compile`
Expected: 성공(경고 없음). 아직 소비자가 없다.

- [x] **Step 5: 커밋**

```bash
git add decode/src/main/java/dev/krillin/huginn/decode/StreamEvidence.java \
        decode/src/main/java/dev/krillin/huginn/decode/Decoded.java \
        decode/src/main/java/dev/krillin/huginn/decode/ProtocolDecoder.java
git commit -m "feat: 이음매 타입 셋 — 프로토콜 지식은 이 뒤에 있다"
```

---

### Task 2: `TrafficObserver`와 `ModbusDecoder` — 순회기와 판정기를 가른다

**Files:**
- Create: `decode/src/main/java/dev/krillin/huginn/decode/TrafficObserver.java`
- Create: `decode/src/main/java/dev/krillin/huginn/decode/ModbusDecoder.java`
- Modify: `decode/src/main/java/dev/krillin/huginn/decode/ModbusObserver.java` (위임으로 축소)

**이 태스크에 새 테스트는 없다.** `ModbusObserverTest` 20건이 리팩터링 그물이고, 그 파일을 고쳐야 한다면 리팩터링이 아니라 동작 변경을 한 것이다.

- [x] **Step 1: 지금 동작을 초록으로 확인해 기준선을 잡는다**

Run: `mvn -pl decode -am test | grep "Tests run:"`
Expected: `ModbusObserverTest` `Tests run: 20, Failures: 0`

- [x] **Step 2: `ModbusDecoder` 작성 — 기존 로직을 옮겨 담는다**

`ModbusObserver`의 `clientDirection`·`observationOf`·`Direction` 을 이 클래스로 **판정 로직 그대로** 옮긴다. 옮기면서 고치면 무엇이 회귀를 냈는지 알 수 없다.

**다만 세 곳은 그대로 옮길 수 없다. 무엇을 어떻게 바꿔야 하는지 미리 적는다 — 여기가 이 태스크에서 가장 막히기 쉬운 지점이다.**

| 원래 | 새 형태 | 이유 |
|---|---|---|
| `clientDirection`이 `decoded.framing().frames()` 로 캐시된 프레임을 읽는다 | **스트림마다 `ModbusFramer.frames(evidence.stream().contiguousPrefix())`를 다시 부른다** | `StreamEvidence`는 프레임을 노출하지 않는다(설계 §3). 프로토콜 지식이 순회기로 새지 않게 하려고 치르는 비용이며, 설계가 "두 번 프레이밍"으로 이미 인정했다 |
| `conversations`가 `List<List<Decoded>>`를 돌려주며 프레이밍까지 한다 | `TrafficObserver`로 옮기고 **`List<List<TcpStream>>`을 돌려준다.** 프레이밍은 하지 않는다 | 순회기는 프로토콜을 몰라야 한다 |
| `find(List<Decoded>, Direction)` | `find(List<StreamEvidence>, Direction)` | 시그니처만 바뀐다 |

**이름 충돌 주의.** `ModbusObserver` 안에 `private record Decoded(TcpStream, FramingResult)` 가 이미 있고, Task 1이 같은 패키지에 이음매용 `Decoded` 를 만들었다. Step 5에서 `ModbusObserver`를 줄이면 사라지지만 **Step 2~3이 먼저 온다.** 옮길 때 그 private record 를 함께 지우거나, Step 5를 먼저 하고 컴파일 오류를 따라가며 채우는 편이 낫다.

```java
package dev.krillin.huginn.decode;

import dev.krillin.huginn.pcap.TcpStream;
import dev.krillin.huginn.reconcile.Endpoint;
import dev.krillin.huginn.reconcile.Observation;
import dev.krillin.huginn.reconcile.Protocol;

import java.util.ArrayList;
import java.util.List;

/**
 * Modbus/TCP 판정. 1차의 {@code ModbusObserver} 안에 있던 프로토콜 고유 로직이 그대로 왔다 —
 * S1(SYN)·S2(PDU 형태) 신호와 결합 규칙 R1~R5, 함수코드 매핑.
 */
final class ModbusDecoder implements ProtocolDecoder {

    @Override public Protocol protocol() { return Protocol.MODBUS_TCP; }

    @Override
    public StreamEvidence scan(TcpStream stream) {
        FramingResult framing = ModbusFramer.frames(stream.contiguousPrefix());
        return new StreamEvidence(stream, framing.frames().size(), framing.undecodedBytes() > 0);
    }

    @Override
    public Decoded decode(List<StreamEvidence> conversation) {
        Direction bySyn = synSignal(conversation);
        ShapeSignal byShape = shapeSignal(conversation);

        if (byShape.contradiction()) {
            // R1 — 양쪽이 같은 형태다. 요청 쪽 모순일 때만 "요청 방향이 둘"이다.
            return Decoded.undecided(byShape.bothRequest());
        }
        if (bySyn != null && byShape.direction() != null && !bySyn.equals(byShape.direction())) {
            return Decoded.undecided(false);   // R2 — 두 신호가 어긋난다
        }
        Direction chosen = byShape.direction() != null ? byShape.direction() : bySyn;
        if (chosen == null) {
            return Decoded.undecided(false);   // R4 — 둘 다 미성립
        }
        StreamEvidence client = find(conversation, chosen);
        if (client == null) {
            return Decoded.undecided(false);   // R5 — 고른 방향이 캡처에 없다
        }

        List<Observation> observations = new ArrayList<>();
        for (ModbusFrame frame : ModbusFramer.frames(client.stream().contiguousPrefix()).frames()) {
            observations.add(observationOf(client.stream(), frame));
        }
        return new Decoded(observations, client, false, false);
    }
    // … synSignal · shapeSignal · find · observationOf · Direction 은 ModbusObserver 에서 그대로 옮긴다
}
```

`shapeSignal`은 기존 `clientDirection`의 형태 판정 부분을 그대로 옮기되 결과를 작은 record 로 낸다:

```java
    /**
     * @param contradiction R1 — 양쪽이 같은 형태다
     * @param bothRequest   그 모순이 <b>양쪽 다 REQUEST_ONLY</b> 인 경우인가.
     *                      양쪽이 RESPONSE_ONLY 인 R1 은 요청 방향이 <b>0 개</b>라 false 다 —
     *                      설계 §3 의 bothDirectionsRequested 계약이 그 둘을 구별한다
     */
    private record ShapeSignal(Direction direction, boolean contradiction, boolean bothRequest) { }
```

- [x] **Step 3: `TrafficObserver` 작성 — 순회와 계수**

```java
package dev.krillin.huginn.decode;

import dev.krillin.huginn.pcap.TcpStream;
import dev.krillin.huginn.reconcile.Access;
import dev.krillin.huginn.reconcile.Endpoint;
import dev.krillin.huginn.reconcile.Observation;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 대화 순회와 계수. <b>프로토콜을 모른다.</b>
 *
 * <p>대화는 4-tuple 을 뒤집어 묶고, 순서는 {@code LinkedHashMap} 으로 최초 등장 순서를 유지한다 —
 * 리포트의 결정성이 여기서 시작된다.
 */
public final class TrafficObserver {

    private static final List<ProtocolDecoder> DECODERS =
        List.of(new ModbusDecoder());   // Task 9 에서 S7Decoder 가 추가된다

    private TrafficObserver() {
    }

    /** cli 가 부르는 유일한 판. */
    public static ObservationResult observe(List<TcpStream> streams) {
        return observe(streams, DECODERS);
    }

    static ObservationResult observe(List<TcpStream> streams, List<ProtocolDecoder> decoders) {
        return observeWithDiagnostics(streams, decoders).result();
    }

    static Diagnosed observeWithDiagnostics(List<TcpStream> streams, List<ProtocolDecoder> decoders) {
        List<Observation> observations = new ArrayList<>();
        int decoded = 0, undecidable = 0, skipped = 0, multiClaim = 0, bothDirections = 0;

        for (List<TcpStream> conversation : conversations(streams)) {
            List<ProtocolDecoder> claimers = new ArrayList<>();
            Map<ProtocolDecoder, List<StreamEvidence>> evidence = new LinkedHashMap<>();
            for (ProtocolDecoder decoder : decoders) {
                List<StreamEvidence> scanned = new ArrayList<>();
                boolean claims = false;
                for (TcpStream stream : conversation) {
                    StreamEvidence one = decoder.scan(stream);
                    scanned.add(one);
                    claims |= one.frameCount() > 0;
                }
                evidence.put(decoder, scanned);
                if (claims) {
                    claimers.add(decoder);
                }
            }

            // 대상 외가 절단·갭을 이긴다(1차 우선순위 규칙).
            if (claimers.isEmpty()) {
                skipped++;
                continue;
            }
            if (claimers.size() > 1) {
                multiClaim++;   // 설계 §3 — 등록 순서로 이기되 몇 번 일어났는지는 센다
            }

            ProtocolDecoder winner = claimers.get(0);
            List<StreamEvidence> conversationEvidence = evidence.get(winner);
            Decoded result = winner.decode(conversationEvidence);
            if (result.bothDirectionsRequested()) {
                bothDirections++;
            }

            // 아래 셋은 순서 있는 사슬이며 먼저 맞는 것이 이긴다.
            if (result.client() == null) {
                observations.add(undecidableOf(conversationEvidence.get(0).stream(), winner));
                undecidable++;
            } else if (result.requestObservations().isEmpty()) {
                observations.add(undecidableOf(result.client().stream(), winner));
                undecidable++;
            } else {
                observations.addAll(result.requestObservations());
                decoded++;
                StreamEvidence client = result.client();
                if (client.leftoverBytes() || client.stream().hasGap()
                    || client.stream().truncated() || result.tailUndecidable()) {
                    observations.add(undecidableOf(client.stream(), winner));
                }
            }
        }

        return new Diagnosed(
            new ObservationResult(List.copyOf(observations), decoded, undecidable, skipped),
            multiClaim, bothDirections);
    }
    // conversations · conversationKey 는 ModbusObserver 에서 그대로 옮긴다
    // undecidableOf 는 protocol 을 winner.protocol() 로 받도록만 바꾼다
}
```

> **꼬리 관찰의 주소는 언제나 `client` 것이다** — `tailUndecidable`이 서버 방향의 사건(Userdata·COTP 분할)에서 비롯됐더라도 그렇다. 1차와 같은 선택이며, 근거 줄에 찍히는 주소가 구현자 재량이 되지 않게 한다.

- [x] **Step 4: `Diagnosed` 작성**

```java
package dev.krillin.huginn.decode;

/**
 * 진단까지 함께 낸 결과. <b>테스트 전용</b>이며 {@link ObservationResult} 와 리포트는 손대지 않는다.
 *
 * @param multiClaimConversations 한 대화에서 둘 이상이 주장한 횟수(설계 §3)
 * @param bothDirectionRequestConversations 순회기가 {@code Decoded.bothDirectionsRequested} 가
 *        참인 대화를 센 것. <b>프로토콜 혼합 계수</b>이며 이긴 해독기를 가리지 않는다
 */
record Diagnosed(ObservationResult result,
                 int multiClaimConversations,
                 int bothDirectionRequestConversations) {
}
```

- [x] **Step 5: `ModbusObserver` 를 위임으로 축소**

옮겨간 로직을 전부 지우고 아래만 남긴다. **`observe(List<TcpStream>)` 시그니처는 그대로 둔다** — `ModbusObserverTest` 20건이 이것을 부른다.

```java
package dev.krillin.huginn.decode;

import dev.krillin.huginn.pcap.TcpStream;

import java.util.List;

/**
 * Modbus 전용 진입점. <b>Modbus 해독기 하나만</b> 등록해 순회기를 돌린다.
 *
 * <p>남겨둔 이유는 {@code ModbusObserverTest} 20건이 이것을 부르고, 그 테스트가 증명하려는 것이
 * Modbus 판정이지 다중 프로토콜 공존이 아니기 때문이다. 공존은 별도 테스트가 증명한다.
 */
public final class ModbusObserver {

    private ModbusObserver() {
    }

    public static ObservationResult observe(List<TcpStream> streams) {
        return TrafficObserver.observe(streams, List.of(new ModbusDecoder()));
    }
}
```

- [x] **Step 6: 기존 테스트가 무변경으로 통과하는지 확인**

Run: `mvn -pl decode -am test | grep "Tests run:"`
Expected: `ModbusObserverTest` `Tests run: 20, Failures: 0` — **테스트 파일은 한 글자도 고치지 않았다.**

Run: `git diff HEAD --stat -- decode/src/test cli/src/test`
Expected: **빈 출력.** 테스트가 바뀌었다면 리팩터링이 아니라 동작 변경이다. 되돌리고 원인을 찾는다.

- [x] **Step 7: 커밋**

```bash
git add decode/src/main
git commit -m "refactor: 대화 순회와 Modbus 판정을 가른다 — 동작은 그대로"
```

---

### Task 3: `Pipeline` 배선 — §7 예산 세 줄

**Files:**
- Modify: `cli/src/main/java/dev/krillin/huginn/cli/Pipeline.java` (5행 import · 23행 javadoc · 39행 호출)

- [x] **Step 1: 세 곳을 바꾼다**

```java
import dev.krillin.huginn.decode.TrafficObserver;          // 5행
...
 * {@code FrameDecoder}(대상 외 패킷), {@code TrafficObserver}(대화 셋), {@code Reconciler}   // 23행
...
        ObservationResult observed = TrafficObserver.observe(streams);                       // 39행
```

- [x] **Step 2: 전체 테스트 통과 확인**

Run: `mvn test | grep -E "Tests run:|BUILD"`
Expected: `BUILD SUCCESS`, 총 157건 그대로.

- [x] **Step 3: 이음매 예산이 지켜졌는지 지금 한 번 센다**

Run: `git diff --stat $BASE..HEAD -- pcap/src/main contract/src/main reconcile/src/main cli/src/main`
Expected: `cli/.../Pipeline.java | 6 +++---` 한 줄만(3줄 수정 = 추가 3 + 삭제 3). `Protocol.java`는 Task 8에서 더해진다.

- [x] **Step 4: 커밋**

```bash
git add cli/src/main/java/dev/krillin/huginn/cli/Pipeline.java
git commit -m "refactor: 파이프라인이 프로토콜 중립 순회기를 부른다"
```

---

## Chunk 2: S7comm 해독

이 청크의 결정 셋을 먼저 못박는다. 미루면 구현자가 임의로 정하게 된다.

| 결정 | 값 | 이유 |
|---|---|---|
| 비-S7 TPKT | **소비하되 세지 않고 `leftoverBytes`에도 넣지 않는다** | 실제 클라이언트 스트림은 COTP 연결 요청(CR)으로 시작한다. 거기서 멈추면 `frameCount`가 0이 되어 대화가 대상 외로 떨어지고 **Job 16만 개가 사라진다.** `leftoverBytes`에 넣으면 CR/CC만 오간 대화에 근거 없는 꼬리 `UNDECIDABLE`이 붙는다 |
| 길이 정합성 | `TPKT len == 4 + (li+1) + 헤더길이 + param-len + data-len` | MBAP length 검사에 대응하는 반증 장치다. 어긋나면 그 지점부터 남은 전부가 미해독 |
| S7 헤더 길이 | ROSCTR 1·7 은 10바이트, 2·3 은 오류 2바이트가 붙어 12바이트 | 이걸 틀리면 길이 정합성이 응답 프레임마다 깨져 응답이 통째로 미해독이 된다 |
| COTP 분할 | EOT=0 이면 **거기서 멈추고** 남은 바이트를 미해독으로, 그리고 분할 표시를 남긴다 | 재조립은 TCP 재조립을 한 층 더 쌓는 일이다(설계 §2) |
| 관찰 대상 | **ROSCTR 1 만.** 2·3 은 응답, 7 은 해석하지 않음 | 설계 §5 |
| A단계의 CONTROL | `0x28`·`0x29`·`0x1A`~`0x1F` 는 **아직 `UNDECIDABLE`** 이다 | B단계에서 CONTROL 로 올린다. A에서 미리 올리면 검증 없는 판정이 리포트에 나간다 |

### Task 4: `S7Fixtures` — 바이트를 손으로 짜지 않는다

**Files:**
- Create: `decode/src/test/java/dev/krillin/huginn/decode/S7Fixtures.java`

`ModbusFixtures` 선례를 그대로 따른다 — **`public final class`이고 메서드도 전부 `public static`이다.** Task 8·9는 물론 B단계의 `cli` E2E도 test-jar 로 이것을 쓴다. `private`이면 그때 컴파일이 깨진다.

> **이 태스크만 픽스처를 테스트보다 먼저 쓴다.** 1차의 `PcapBuilder`와 같은 예외다 — 픽스처가 없으면 그것을 검증할 테스트조차 쓸 수 없다. Task 5부터는 테스트가 먼저다.

- [x] **Step 1: 픽스처 작성**

```java
package dev.krillin.huginn.decode;

import java.io.ByteArrayOutputStream;

/**
 * S7comm 바이트 픽스처. 프레임을 손으로 짜면 길이 필드를 매번 다시 계산해야 하고,
 * 그 계산이 틀리면 테스트가 프레이머가 아니라 픽스처를 검증하게 된다.
 */
public final class S7Fixtures {

    public static final int ROSCTR_JOB = 1;
    public static final int ROSCTR_ACK_DATA = 3;
    public static final int ROSCTR_USERDATA = 7;

    private S7Fixtures() {
    }

    /** ROSCTR 1. parameter 는 함수코드부터 시작한다. */
    public static byte[] job(byte[] parameter) {
        return frame(ROSCTR_JOB, parameter, new byte[0], true);
    }

    /** ROSCTR 3 — 헤더에 오류 클래스·코드 2바이트가 더 붙는다. */
    public static byte[] ackData(byte[] parameter, byte[] data) {
        return frame(ROSCTR_ACK_DATA, parameter, data, true);
    }

    /** ROSCTR 7. */
    public static byte[] userdata(byte[] parameter) {
        return frame(ROSCTR_USERDATA, parameter, new byte[0], true);
    }

    /** EOT 비트가 꺼진 조각. 프레이머는 여기서 멈춰야 한다. */
    public static byte[] fragmented(byte[] parameter) {
        return frame(ROSCTR_JOB, parameter, new byte[0], false);
    }

    /** COTP 연결 요청(CR, 0xE0) — TPKT 로는 유효하지만 S7 이 아니다. */
    public static byte[] connectRequest() {
        byte[] cotp = {0x11, (byte) 0xE0, 0, 0, 0, 1, 0, (byte) 0xC0, 1, 0x0A,
                       (byte) 0xC1, 2, 1, 2, (byte) 0xC2, 2, 1, 2};
        return tpkt(cotp);
    }

    /** 0x04 Read Var. */
    public static byte[] readVar(byte[]... items) { return varParameter(0x04, items); }

    /** 0x05 Write Var. */
    public static byte[] writeVar(byte[]... items) { return varParameter(0x05, items); }

    /** 0xF0 Setup Communication — 파라미터에 항목이 없다. */
    public static byte[] setupCommunication() {
        return new byte[] {(byte) 0xF0, 0, 0, 1, 0, 1, 0, (byte) 0xF0};
    }

    /** 1200SYM(0xb2) 주소 항목. */
    public static byte[] sym(int area1, int area2, int... lids) {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        body.write(0xB2);                     // syntax id
        body.write(0xFF);                     // reserved
        writeU16(body, area1);
        writeU16(body, area2);
        body.writeBytes(new byte[] {(byte) 0xEA, 0x2D, (byte) 0xB0, (byte) 0xD9});   // CRC
        for (int lid : lids) {
            body.write(0x40 | ((lid >>> 24) & 0x0F));    // LID flags 4 = Obtain by LID
            body.write((lid >>> 16) & 0xFF);
            body.write((lid >>> 8) & 0xFF);
            body.write(lid & 0xFF);
        }
        return item(body.toByteArray());
    }

    /** S7ANY(0x10) 주소 항목. address 는 바이트 주소, bit 는 0~7. */
    public static byte[] s7any(int area, int dbNumber, int address, int bit) {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        body.write(0x10);                     // syntax id
        body.write(0x02);                     // transport size = BYTE
        writeU16(body, 1);                    // length
        writeU16(body, dbNumber);
        body.write(area);
        int bitAddress = address * 8 + bit;
        body.write((bitAddress >>> 16) & 0xFF);
        body.write((bitAddress >>> 8) & 0xFF);
        body.write(bitAddress & 0xFF);
        return item(body.toByteArray());
    }

    public static byte[] concat(byte[]... parts) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] part : parts) {
            out.writeBytes(part);
        }
        return out.toByteArray();
    }

    /** 항목 하나를 `12 <len> <body>` 로 감싼다 — len 은 syntax id 부터 센다. */
    private static byte[] item(byte[] body) {
        if (body.length > 255) {
            throw new IllegalArgumentException("항목 길이 필드는 1바이트다: " + body.length);
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(0x12);
        out.write(body.length);
        out.writeBytes(body);
        return out.toByteArray();
    }

    private static byte[] varParameter(int function, byte[]... items) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(function);
        out.write(items.length);
        for (byte[] one : items) {
            out.writeBytes(one);
        }
        return out.toByteArray();
    }

    private static byte[] frame(int rosctr, byte[] parameter, byte[] data, boolean endOfTransmission) {
        ByteArrayOutputStream s7 = new ByteArrayOutputStream();
        s7.write(0x32);
        s7.write(rosctr);
        writeU16(s7, 0);                       // redundancy id
        writeU16(s7, 0x0100);                  // pdu reference
        writeU16(s7, parameter.length);
        writeU16(s7, data.length);
        if (rosctr == 2 || rosctr == 3) {
            s7.write(0);                       // error class
            s7.write(0);                       // error code
        }
        s7.writeBytes(parameter);
        s7.writeBytes(data);

        ByteArrayOutputStream cotp = new ByteArrayOutputStream();
        cotp.write(0x02);                                       // li
        cotp.write(0xF0);                                       // DT Data
        cotp.write(endOfTransmission ? 0x80 : 0x00);            // tpdu number | eot
        cotp.writeBytes(s7.toByteArray());
        return tpkt(cotp.toByteArray());
    }

    /** TPKT 로 감싼다 — 길이는 헤더 4바이트를 포함한다. */
    public static byte[] tpkt(byte[] payload) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(0x03);
        out.write(0x00);
        writeU16(out, 4 + payload.length);
        out.writeBytes(payload);
        return out.toByteArray();
    }

    private static void writeU16(ByteArrayOutputStream out, int value) {
        out.write((value >>> 8) & 0xFF);
        out.write(value & 0xFF);
    }
}
```

- [x] **Step 2: 픽스처가 설계 §4의 실제 바이트를 재현하는지 확인하는 테스트**

`decode/src/test/java/dev/krillin/huginn/decode/S7FixturesTest.java`:

```java
@Test
void 설계_문서의_실제_캡처_바이트를_재현한다() {
    // 4SICS 151020 에서 뜬 Write Var 요청 한 건(설계 §4).
    // 픽스처가 실물과 다르면 이 계획의 모든 테스트가 허구를 검증하게 된다.
    byte[] frame = S7Fixtures.job(S7Fixtures.writeVar(S7Fixtures.sym(0x0000, 0x0052, 16)));

    assertEquals(0x03, frame[0] & 0xFF);
    assertEquals(0x00, frame[1] & 0xFF);
    assertEquals(4 + 3 + 10 + 18, ((frame[2] & 0xFF) << 8) | (frame[3] & 0xFF),
        "TPKT 길이 = 4 + COTP 3 + S7 헤더 10 + 파라미터 18");
    assertEquals(0x32, frame[7] & 0xFF, "S7 프로토콜 id");
    assertEquals(0x01, frame[8] & 0xFF, "ROSCTR Job");
}
```

> 실물은 데이터 5바이트가 더 붙은 Write 요청이지만, 픽스처의 `job()`은 데이터 없는 판이다. 길이 계산 규칙이 같다는 것만 고정하면 충분하다 — 데이터 있는 판은 `ackData`가 덮는다.

- [x] **Step 3: 통과 확인**

Run: `mvn -pl decode -am test | grep "Tests run:"`
Expected: `S7FixturesTest` `Tests run: 1, Failures: 0`

- [x] **Step 4: 커밋**

```bash
git add decode/src/test/java/dev/krillin/huginn/decode/S7Fixtures.java \
        decode/src/test/java/dev/krillin/huginn/decode/S7FixturesTest.java
git commit -m "test: S7 픽스처 — 설계 문서의 실제 캡처 바이트를 재현한다"
```

---

### Task 5: `S7Framer` — TPKT → COTP → S7

**Files:**
- Create: `decode/src/main/java/dev/krillin/huginn/decode/S7Frame.java`
- Create: `decode/src/main/java/dev/krillin/huginn/decode/S7FramingResult.java`
- Create: `decode/src/main/java/dev/krillin/huginn/decode/S7Framer.java`
- Test: `decode/src/test/java/dev/krillin/huginn/decode/S7FramerTest.java`

- [x] **Step 1: 실패하는 테스트 작성**

```java
@Test
void 유효한_Job_프레임을_뽑는다() {
    S7FramingResult r = S7Framer.frames(S7Fixtures.job(S7Fixtures.readVar(sym(0, 0x52, 16))));
    assertEquals(1, r.frames().size());
    assertEquals(1, r.frames().get(0).rosctr());
    assertEquals(0x04, r.frames().get(0).functionCode());
    assertEquals(0, r.undecodedBytes());
    assertFalse(r.fragmented());
}

@Test
void 한_세그먼트의_TPKT_여러_개를_전부_뽑는다() {
    // 실캡처에 한 패킷당 PDU 가 여럿인 경우가 있다(tshark 가 쉼표로 나열하는 그것).
    S7FramingResult r = S7Framer.frames(S7Fixtures.concat(
        S7Fixtures.job(S7Fixtures.readVar(S7Fixtures.sym(0, 0x52, 16))),
        S7Fixtures.job(S7Fixtures.readVar(S7Fixtures.sym(0, 0x52, 17))),
        S7Fixtures.job(S7Fixtures.setupCommunication())));
    assertEquals(3, r.frames().size());
    assertEquals(0xF0, r.frames().get(2).functionCode());
    assertEquals(0, r.undecodedBytes());
}

@Test
void 응답은_헤더가_12바이트다() {
    // ROSCTR 3 은 오류 클래스·코드가 더 붙는다. 10 으로 읽으면 길이 정합성이 깨져
    // 응답이 통째로 미해독이 되고, tshark 대조에서 응답 수가 안 맞는다.
    S7FramingResult r = S7Framer.frames(S7Fixtures.ackData(new byte[]{0x04, 0x01}, new byte[]{(byte) 0xFF, 4, 0, 2, 0, 1}));
    assertEquals(1, r.frames().size());
    assertEquals(3, r.frames().get(0).rosctr());
}

@Test
void COTP_연결요청은_소비하되_세지_않는다() {
    // 이 테스트가 기대값 표의 존폐를 가른다 — 실제 클라이언트 스트림은 CR 로 시작한다.
    S7FramingResult r = S7Framer.frames(S7Fixtures.connectRequest());
    assertTrue(r.frames().isEmpty());
    assertEquals(0, r.undecodedBytes(), "우리 관심사가 아닌 프레임이지 미해독 바이트가 아니다");
}

@Test
void 연결요청_뒤의_Job_을_정상적으로_뽑는다() {
    // 첫 비-S7 TPKT 에서 멈추는 구현이면 frameCount 가 0 이 되어 대화가 대상 외로 떨어지고
    // 실캡처의 Job 16만 개가 통째로 사라진다.
    S7FramingResult r = S7Framer.frames(S7Fixtures.concat(
        S7Fixtures.connectRequest(),
        S7Fixtures.job(S7Fixtures.readVar(sym(0, 0x52, 16))),
        S7Fixtures.job(S7Fixtures.readVar(sym(0, 0x52, 17)))));
    assertEquals(2, r.frames().size());
    assertEquals(0, r.undecodedBytes());
}

@Test
void 페이로드가_0x32가_아니면_소비하되_세지_않는다() {
    // TPKT/COTP 는 ISO-on-TCP 일반 규약이라 S7 전용이 아니다.
    byte[] notS7 = S7Fixtures.tpkt(new byte[]{0x02, (byte) 0xF0, (byte) 0x80,
        0x33, 0x01, 0, 0, 0, 1, 0, 2, 0, 0});          // 0x33 — S7 이 아니다
    S7FramingResult r = S7Framer.frames(S7Fixtures.concat(
        notS7, S7Fixtures.job(S7Fixtures.readVar(S7Fixtures.sym(0, 0x52, 16)))));
    assertEquals(1, r.frames().size(), "S7 프레임만 센다");
    assertEquals(0, r.undecodedBytes(), "미해독이 아니라 관심사가 아닌 프레임이다");
}

@Test
void TPKT_길이_정합성이_깨지면_그_지점부터_미해독이다() {
    // param-len 을 부풀린 프레임. 남은 전부가 미해독이고 재동기화하지 않는다.
    byte[] frame = S7Fixtures.job(S7Fixtures.readVar(S7Fixtures.sym(0, 0x52, 16)));
    frame[13] = (byte) (frame[13] + 1);                 // S7 헤더 param-len 의 **상위** 바이트(+256)
    byte[] stream = S7Fixtures.concat(frame, S7Fixtures.job(S7Fixtures.setupCommunication()));

    S7FramingResult r = S7Framer.frames(stream);

    assertTrue(r.frames().isEmpty());
    assertEquals(stream.length, r.undecodedBytes(), "뒤의 유효 프레임도 재동기화로 건지지 않는다");
}

@Test
void 마지막_프레임이_잘려도_예외가_아니라_미해독_바이트다() {
    // 캡처가 프레임 중간에서 끝나는 것은 정상적인 상황이다(1차 프레이머와 같은 판단).
    byte[] whole = S7Fixtures.job(S7Fixtures.readVar(S7Fixtures.sym(0, 0x52, 16)));
    byte[] stream = S7Fixtures.concat(whole, Arrays.copyOf(whole, whole.length - 3));

    S7FramingResult r = S7Framer.frames(stream);

    assertEquals(1, r.frames().size());
    assertEquals(whole.length - 3, r.undecodedBytes());
}

@Test
void COTP_분할이면_거기서_멈추고_분할을_표시한다() {
    S7FramingResult r = S7Framer.frames(S7Fixtures.concat(
        S7Fixtures.job(S7Fixtures.readVar(sym(0, 0x52, 16))),
        S7Fixtures.fragmented(S7Fixtures.readVar(sym(0, 0x52, 17)))));
    assertEquals(1, r.frames().size());
    assertTrue(r.fragmented());
    assertTrue(r.undecodedBytes() > 0);
}

@Test
void 스트림_중간부터_시작해도_재동기화하지_않는다() {
    // 앞에 이전 프레임의 꼬리 4바이트. TPKT 매직이 어긋나므로 프레임 0개다.
    byte[] stream = S7Fixtures.concat(new byte[]{0x00, 0x02, 0x00, 0x01},
        S7Fixtures.job(S7Fixtures.readVar(S7Fixtures.sym(0, 0x52, 16))));

    S7FramingResult r = S7Framer.frames(stream);

    assertTrue(r.frames().isEmpty());
    assertEquals(stream.length, r.undecodedBytes());
}

@Test
void TPKT가_아닌_바이트는_프레임이_아니다() {
    S7FramingResult r = S7Framer.frames("SSH-2.0-OpenSSH_9.0\r\n".getBytes(US_ASCII));
    assertTrue(r.frames().isEmpty());
}

@Test
void Userdata도_프레임으로_센다() {
    // 관찰은 만들지 않지만(§5) 그 스트림이 S7 이라는 증거는 된다 — 대상 외가 아니다.
    S7FramingResult r = S7Framer.frames(S7Fixtures.userdata(new byte[]{0x00, 0x01, 0x12, 0x04}));
    assertEquals(1, r.frames().size());
    assertEquals(7, r.frames().get(0).rosctr());
}
```

- [x] **Step 2: 실패 확인**

Run: `mvn -pl decode -am test | grep "Tests run:"`
Expected: 컴파일 실패 — `S7Framer`·`S7FramingResult` 없음

- [x] **Step 3: 구현**

```java
/** @param parameter 파라미터 바이트 전체. ROSCTR 1 이면 첫 바이트가 함수코드다. */
public record S7Frame(int rosctr, byte[] parameter) {
    /** ROSCTR 1 이 아니거나 파라미터가 비었으면 -1. */
    public int functionCode() {
        return parameter.length > 0 ? parameter[0] & 0xFF : -1;
    }
}
```

```java
/** @param fragmented COTP 분할(EOT=0)을 만나 자르기를 멈췄는가. 설계 §2 — 재조립하지 않는다 */
public record S7FramingResult(List<S7Frame> frames, int undecodedBytes, boolean fragmented) {
}
```

`S7Framer.frames(byte[] stream)` 규칙:

1. 잔여 < 7 이면 남은 바이트를 미해독으로 누적하고 종료 (TPKT 4 + COTP 최소 3)
2. `stream[off] != 0x03 || stream[off+1] != 0x00` → 그 지점부터 남은 전부 미해독, 종료
3. `len = u16(off+2)`; `len < 7` 이면 미해독, 종료. 잔여 < `len` 이면 절단 — 미해독, 종료
4. `li = u8(off+4)`; COTP 헤더 = `li + 1`. `li < 2` 이거나 `4 + li + 1 > len` 이면 미해독, 종료
5. `cotpType = u8(off+5)`; **`0xF0`(DT)이 아니면 `off += len` 하고 계속** — 세지 않고 미해독에도 넣지 않는다
6. DT 이면 `eot = (u8(off+6) & 0x80) != 0`. **`!eot` 이면 `fragmented = true`, 남은 전부 미해독, 종료**
7. 페이로드 = `off + 4 + (li+1)` 부터 `len - 4 - (li+1)` 바이트. 길이 < 10 이거나 첫 바이트 != `0x32` → `off += len` 하고 계속(세지 않는다)
8. `rosctr = payload[1]`; 헤더 = `rosctr == 2 || rosctr == 3 ? 12 : 10`. 페이로드 길이 < 헤더면 `off += len` 계속
9. `paramLen = u16(payload+6)`, `dataLen = u16(payload+8)`. **`len != 4 + (li+1) + 헤더 + paramLen + dataLen` 이면 미해독, 종료**
10. 프레임을 만들고 `off += len`

**포트를 인자로 받지 않는다.** 102 라는 관례는 502 와 같은 이유로 쓰지 않는다.

- [x] **Step 4: 통과 확인**

Run: `mvn -pl decode -am test | grep "Tests run:"`
Expected: `S7FramerTest` `Tests run: 12, Failures: 0`

- [x] **Step 5: 커밋**

```bash
git add decode/src/main decode/src/test
git commit -m "feat: S7 프레이밍 — 비-S7 TPKT 는 소비하되 세지 않는다"
```

---

### Task 6: `S7Access` — 함수코드 → `Access`

**Files:**
- Create: `decode/src/main/java/dev/krillin/huginn/decode/S7Access.java`
- Test: `decode/src/test/java/dev/krillin/huginn/decode/S7AccessTest.java`

- [x] **Step 1: 실패하는 테스트 작성**

```java
@Test void 읽기는_0x04다() { assertEquals(Access.READ, S7Access.of(0x04)); }
@Test void 쓰기는_0x05다() { assertEquals(Access.WRITE, S7Access.of(0x05)); }

@Test
void 세션_설정은_UNDECIDABLE이다() {
    // 0xF0 은 데이터 접근이 아니다. READ 로 치면 세션마다 읽기 관찰이 하나씩 생긴다.
    assertEquals(Access.UNDECIDABLE, S7Access.of(0xF0));
}

@ParameterizedTest @ValueSource(ints = {0x28, 0x29, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F})
void A단계에서_제어_계열은_아직_UNDECIDABLE이다(int fc) {
    // B단계에서 CONTROL 로 올린다. 여기서 미리 올리면 검증되지 않은 판정이 리포트에 나간다.
    assertEquals(Access.UNDECIDABLE, S7Access.of(fc));
}

@ParameterizedTest @ValueSource(ints = {0x00, 0x03, 0x99, -1})
void 모르는_함수코드는_UNDECIDABLE이다(int fc) {
    // -1 은 파라미터가 비어 함수코드를 못 읽은 프레임이다(S7Frame.functionCode 계약).
    assertEquals(Access.UNDECIDABLE, S7Access.of(fc));
}
```

- [x] **Step 2: 실패 확인** → 컴파일 실패

- [x] **Step 3: 구현** — `Map<Integer, Access>` 상수표. `ModbusAccess` 와 같은 형태를 쓴다(2차에서 재사용한다고 1차가 적어둔 그 형태다). 표에 없으면 `UNDECIDABLE`.

- [x] **Step 4: 통과 확인** — `Tests run: 15, Failures: 0` (단일 3 + 파라미터 8 + 4)

- [x] **Step 5: 커밋**

```bash
git add decode/src/main decode/src/test
git commit -m "feat: S7 함수코드 → Access, 제어 계열은 B단계까지 UNDECIDABLE"
```

---

### Task 7: `S7ObjectRef` — 1200SYM과 S7ANY

**Files:**
- Create: `decode/src/main/java/dev/krillin/huginn/decode/S7ObjectRef.java`
- Test: `decode/src/test/java/dev/krillin/huginn/decode/S7ObjectRefTest.java`

- [x] **Step 1: 실패하는 테스트 작성**

```java
@Test
void 실캡처의_1200SYM_주소를_표기한다() {
    // 설계 §4 의 실제 바이트: area1 0x0000 · area2 0x0052(Flags M) · LID 16
    assertEquals("sym:m/16", S7ObjectRef.of(S7Fixtures.readVar(S7Fixtures.sym(0x0000, 0x0052, 16))));
}

@Test
void LID가_여럿이면_슬래시로_잇는다() {
    assertEquals("sym:m/16/3", S7ObjectRef.of(S7Fixtures.readVar(S7Fixtures.sym(0, 0x52, 16, 3))));
}

@Test
void area1이_0이_아니면_이름을_지어내지_않는다() {
    // area1 != 0 이면 area2 는 영역 코드가 아니라 DB 번호 계열이다. 실캡처에 0건이라 미검증 경로다.
    assertEquals("sym:0x0001:0x0052/16", S7ObjectRef.of(S7Fixtures.readVar(S7Fixtures.sym(1, 0x52, 16))));
}

@Test
void 아는_area2는_0x0052_하나뿐이다() {
    assertEquals("sym:0x0000:0x0084/16", S7ObjectRef.of(S7Fixtures.readVar(S7Fixtures.sym(0, 0x84, 16))));
}

@Test
void S7ANY_DB_주소를_표기한다() {
    assertEquals("db1.dbx20.0", S7ObjectRef.of(S7Fixtures.readVar(S7Fixtures.s7any(0x84, 1, 20, 0))));
}

@Test
void S7ANY_플래그_주소를_표기한다() {
    assertEquals("m20.3", S7ObjectRef.of(S7Fixtures.readVar(S7Fixtures.s7any(0x83, 0, 20, 3))));
}

@Test
void 항목이_여럿이면_첫_항목과_개수를_적는다() {
    String ref = S7ObjectRef.of(S7Fixtures.readVar(
        S7Fixtures.sym(0, 0x52, 16), S7Fixtures.sym(0, 0x52, 17), S7Fixtures.sym(0, 0x52, 18)));
    assertEquals("sym:m/16 (+2)", ref);
}

@Test
void 항목이_없는_함수는_함수코드만_적는다() {
    assertEquals("fc:240", S7ObjectRef.of(S7Fixtures.setupCommunication()));
}

@Test
void 파라미터가_짧으면_지어내지_않는다() {
    assertEquals("fc:4", S7ObjectRef.of(new byte[]{0x04, 0x01, 0x12}));
}

@Test
void 입력과_출력도_표기한다() {
    assertEquals("i0.0", S7ObjectRef.of(S7Fixtures.readVar(S7Fixtures.s7any(0x81, 0, 0, 0))));
    assertEquals("q4.1", S7ObjectRef.of(S7Fixtures.readVar(S7Fixtures.s7any(0x82, 0, 4, 1))));
}

@Test
void 카운터와_타이머는_비트_주소가_없다() {
    assertEquals("c3", S7ObjectRef.of(S7Fixtures.readVar(S7Fixtures.s7any(0x1C, 0, 3, 0))));
    assertEquals("t7", S7ObjectRef.of(S7Fixtures.readVar(S7Fixtures.s7any(0x1D, 0, 7, 0))));
}

@Test
void 첫_항목을_못_읽어도_항목_수는_적는다() {
    // 항목이 여럿이라는 사실은 첫 항목을 읽었는지와 무관하다.
    byte[] parameter = S7Fixtures.concat(new byte[]{0x04, 0x02, 0x12, 0x02, 0x77, 0x00},
                                         S7Fixtures.sym(0, 0x52, 16));
    assertEquals("fc:4 (+1)", S7ObjectRef.of(parameter));
}
```

- [x] **Step 2: 실패 확인** → 컴파일 실패

- [x] **Step 3: 구현**

`S7ObjectRef.of(byte[] parameter)`:
- `parameter[0]`이 `0x04`·`0x05`가 아니거나 길이 < 2 → `fc:<n>`
- `itemCount = parameter[1]`; 항목이 0개면 `fc:<n>`
- 첫 항목만 읽는다: `0x12 <len> <body>` 형태가 아니면 `fc:<n>`
- **`syntaxId == 0xB2`** — body 는 `syntaxId(1) reserved(1) area1(2) area2(2) crc(4)` 10바이트 + LID `4 × (len-10)/4`.
  `area1 == 0x0000 && area2 == 0x0052` 면 `sym:m/<lid>[/<lid>…]`, 아니면 `sym:0x<area1>:0x<area2>/<lid>…`.
  LID 값은 **하위 28비트**를 10진수로 쓴다(상위 4비트는 플래그다). LID 가 0개면 area 까지만 쓴다
- **`syntaxId == 0x10`** — `transportSize(1) length(2) dbNumber(2) area(1) address(3)`.
  `<byte> = address / 8`, `<bit> = address % 8`. 영역 코드는 설계 §5의 표를 **하나도 빠뜨리지 않는다**:

  | area | 표기 | 예 |
  |---|---|---|
  | `0x84` DB | `db<dbNumber>.dbx<byte>.<bit>` | `db1.dbx20.0` |
  | `0x83` M | `m<byte>.<bit>` | `m20.3` |
  | `0x81` I | `i<byte>.<bit>` | `i0.0` |
  | `0x82` Q | `q<byte>.<bit>` | `q4.1` |
  | `0x1C` C | `c<byte>` | `c3` — 카운터는 비트 주소가 없다 |
  | `0x1D` T | `t<byte>` | `t7` |
  | 그 외 | `fc:<n>` | 지어내지 않는다 |
- 그 밖의 syntax id → `fc:<n>`
- `itemCount > 1` 이면 뒤에 ` (+<itemCount-1>)`. **첫 항목을 못 읽어 `fc:<n>` 이 된 경우에도 붙인다** — 항목이 여럿이라는 사실은 첫 항목을 읽었는지와 무관하다
- `fc:<n>` 의 `<n>` 은 **`parameter[0] & 0xFF`** 다. 부호 있는 byte 로 쓰면 `0xF0` 이 `-16` 으로 나온다

- [x] **Step 4: 통과 확인** — `Tests run: 12, Failures: 0`

- [x] **Step 5: 커밋**

```bash
git add decode/src/main decode/src/test
git commit -m "feat: S7 objectRef — 실캡처는 100% 1200SYM 이고 S7ANY 는 0건이다"
```

---

### Task 8: `S7Decoder` — ROSCTR이 방향을 정한다

**Files:**
- Create: `decode/src/main/java/dev/krillin/huginn/decode/S7Decoder.java`
- Test: `decode/src/test/java/dev/krillin/huginn/decode/S7DecoderTest.java`

테스트는 `TrafficObserver.observe(streams, List.of(new S7Decoder()))` 로 돌린다 — 해독기 단독이 아니라 순회기까지 함께 돌려야 계수 규칙이 검증된다.

공통 헬퍼와 상수(`import static dev.krillin.huginn.decode.S7Fixtures.sym;` 을 함께 둔다 — 아래 스케치가 `sym(...)` 을 한정 없이 부른다):

```java
    private static final String HMI = "10.0.1.20", PLC = "10.0.2.11";
    private static final String A = "10.0.1.30", B = "10.0.2.40";

    private static final byte[] READ_JOB =
        S7Fixtures.job(S7Fixtures.readVar(S7Fixtures.sym(0, 0x52, 16)));
    private static final byte[] READ_ACK =
        S7Fixtures.ackData(new byte[]{0x04, 0x01}, new byte[]{(byte) 0xFF, 4, 0, 2, 0, 1});

    private static TcpStream stream(String src, int sport, String dst, int dport, byte[] bytes) {
        return new TcpStream(Instant.EPOCH, src, sport, dst, dport, bytes, false, false, false);
    }

    private ObservationResult observe(TcpStream... streams) {
        return TrafficObserver.observe(List.of(streams), List.of(new S7Decoder()));
    }

    private Diagnosed observeWithDiagnostics(TcpStream... streams) {
        return TrafficObserver.observeWithDiagnostics(List.of(streams), List.of(new S7Decoder()));
    }
```

- [x] **Step 1: 실패하는 테스트 작성**

```java
@Test
void 요청만_관찰한다() {
    // Job 은 hmi→plc, Ack_Data 는 plc→hmi. 응답까지 관찰하면 정상 통신이 위반이 된다.
    ObservationResult r = observe(
        stream(HMI, 2000, PLC, 102, S7Fixtures.job(S7Fixtures.readVar(sym(0, 0x52, 16)))),
        stream(PLC, 102, HMI, 2000, S7Fixtures.ackData(new byte[]{0x04, 0x01}, new byte[]{(byte) 0xFF, 4, 0, 2, 0, 1})));
    assertEquals(1, r.observations().size());
    assertEquals(HMI, r.observations().get(0).source().address());
    assertEquals(Access.READ, r.observations().get(0).access());
    assertEquals(Protocol.S7COMM, r.observations().get(0).protocol());
    assertEquals(1, r.decodedConversations());
}

@Test
void 응답만_잡힌_캡처는_판정하지_않는다() {
    // 1차 R5 에 해당하는 경우인데 S7 에는 별도 가드가 없다 — 요청 방향이 0 개라 자동으로 걸린다.
    ObservationResult r = observe(stream(PLC, 102, HMI, 2000, READ_ACK));

    assertEquals(1, r.observations().size());
    assertEquals(Access.UNDECIDABLE, r.observations().get(0).access());
    assertEquals(1, r.undecidableConversations());
    assertEquals(0, r.decodedConversations());
}

@Test
void 양쪽_방향에_모두_요청이_있으면_판정하지_않는다() {
    // 한 4-tuple 에 연결이 둘 묶였거나 재조립이 어긋난 것이다. 다수결로 밀어붙이지 않는다.
    Diagnosed d = observeWithDiagnostics(
        stream(A, 102, B, 102, READ_JOB),
        stream(B, 102, A, 102, READ_JOB));
    assertEquals(1, d.result().observations().size());
    assertEquals(Access.UNDECIDABLE, d.result().observations().get(0).access());
    assertEquals(1, d.result().undecidableConversations());
    assertEquals(1, d.bothDirectionRequestConversations(), "요청 방향이 0 개인 경우와 구별된다");
}

@Test
void 응답만_잡힌_경우는_양방향_요청으로_세지_않는다() {
    // 위 테스트의 짝. 둘 다 client == null 이지만 원인이 다르다.
    Diagnosed d = observeWithDiagnostics(stream(PLC, 102, HMI, 2000, READ_ACK));
    assertEquals(1, d.result().undecidableConversations());
    assertEquals(0, d.bothDirectionRequestConversations());
}

@Test
void Userdata만_실린_대화는_UNDECIDABLE_대화다() {
    // 프레임으로는 세이므로 대상 외가 아니다. 그러나 요청 방향이 0 개라 관찰이 없다.
    ObservationResult r = observe(stream(HMI, 2000, PLC, 102, S7Fixtures.userdata(new byte[]{0, 1, 0x12, 4})));
    assertEquals(1, r.observations().size());
    assertEquals(Access.UNDECIDABLE, r.observations().get(0).access());
    assertEquals(1, r.undecidableConversations());
    assertEquals(0, r.skippedConversations());
}

@Test
void Job과_Userdata가_섞이면_해독하고_꼬리를_하나_남긴다() {
    // Userdata 가 몇 개든 꼬리는 한 건이다 — 프레임 수와 무관하다(설계 §5).
    byte[] userdata = S7Fixtures.userdata(new byte[]{0x00, 0x01, 0x12, 0x04});
    ObservationResult r = observe(stream(HMI, 2000, PLC, 102,
        S7Fixtures.concat(READ_JOB, userdata, userdata)));

    assertEquals(2, r.observations().size(), "Job 관찰 1 + 꼬리 1");
    assertEquals(Access.READ, r.observations().get(0).access());
    assertEquals(Access.UNDECIDABLE, r.observations().get(1).access());
    assertEquals("-", r.observations().get(1).objectRef());
    assertEquals(1, r.decodedConversations());
    assertEquals(0, r.undecidableConversations());
}

@Test
void 응답_방향의_Userdata도_꼬리를_만든다() {
    // client 의 잔여만 보는 규칙으로는 못 잡는 경우 — tailUndecidable 이 존재하는 이유다.
    ObservationResult r = observe(
        stream(HMI, 2000, PLC, 102, S7Fixtures.job(S7Fixtures.readVar(sym(0, 0x52, 16)))),
        stream(PLC, 102, HMI, 2000, S7Fixtures.userdata(new byte[]{0, 1, 0x12, 8})));
    assertEquals(2, r.observations().size(), "Job 관찰 1 + 꼬리 1");
    assertEquals(Access.UNDECIDABLE, r.observations().get(1).access());
    assertEquals(HMI, r.observations().get(1).source().address(), "꼬리 주소는 언제나 client 것이다");
    assertEquals(1, r.decodedConversations());
}

@Test
void COTP_분할도_꼬리를_만든다() {
    // 분할은 재조립하지 않는다(설계 §2). 그러나 못 본 것이 있다는 사실은 남긴다.
    ObservationResult r = observe(stream(HMI, 2000, PLC, 102, S7Fixtures.concat(
        READ_JOB, S7Fixtures.fragmented(S7Fixtures.readVar(S7Fixtures.sym(0, 0x52, 17))))));

    assertEquals(2, r.observations().size(), "Job 관찰 1 + 꼬리 1");
    assertEquals(Access.UNDECIDABLE, r.observations().get(1).access());
    assertEquals(1, r.decodedConversations());
}

@Test
void 연결설정만_오간_대화는_대상_외다() {
    ObservationResult r = observe(stream(HMI, 2000, PLC, 102, S7Fixtures.connectRequest()));
    assertEquals(1, r.skippedConversations());
    assertTrue(r.observations().isEmpty());
}

@Test
void 포트가_102가_아니어도_해독한다() {
    // S7 도 Modbus 와 같다 — 우회하는 사람은 포트를 바꾼다.
    ObservationResult r = observe(stream(HMI, 50001, PLC, 40102, READ_JOB));

    assertEquals(1, r.observations().size());
    assertEquals(Access.READ, r.observations().get(0).access());
    assertEquals(1, r.decodedConversations());
}
```

- [x] **Step 2: 실패 확인** → `S7Decoder`·`Protocol.S7COMM` 없음

- [x] **Step 3: `Protocol` 에 상수 추가 — §7 예산의 나머지 절반**

**열거형 선언 줄에 `, S7COMM` 만 더한다. 위의 6줄 javadoc 은 그대로 둔다.** 파일을 통째로 갈아치우면 §7 측정이 `Protocol.java | 10 +++---` 로 부풀어, 이 계획이 존재하는 이유인 그 측정이 흐려진다.

```java
public enum Protocol { MODBUS_TCP, S7COMM }
```

Run: `git diff --stat -- reconcile/src/main`
Expected: `Protocol.java | 2 +-`

- [x] **Step 4: `S7Decoder` 구현**

```java
final class S7Decoder implements ProtocolDecoder {

    @Override public Protocol protocol() { return Protocol.S7COMM; }

    @Override
    public StreamEvidence scan(TcpStream stream) {
        S7FramingResult framing = S7Framer.frames(stream.contiguousPrefix());
        return new StreamEvidence(stream, framing.frames().size(), framing.undecodedBytes() > 0);
    }

    @Override
    public Decoded decode(List<StreamEvidence> conversation) {
        // 요청(ROSCTR 1)을 실은 방향을 찾는다. 0 개거나 2 개면 판정 불가다.
        List<StreamEvidence> requestSides = new ArrayList<>();
        boolean unread = false;                       // Userdata 또는 COTP 분할
        for (StreamEvidence evidence : conversation) {
            S7FramingResult framing = S7Framer.frames(evidence.stream().contiguousPrefix());
            unread |= framing.fragmented();
            boolean hasJob = false;
            for (S7Frame frame : framing.frames()) {
                if (frame.rosctr() == 1) {
                    hasJob = true;
                } else if (frame.rosctr() == 7) {
                    unread = true;                    // 해석하지 않는다(설계 §5)
                }
            }
            if (hasJob) {
                requestSides.add(evidence);
            }
        }
        if (requestSides.size() != 1) {
            return Decoded.undecided(requestSides.size() > 1);
        }

        StreamEvidence client = requestSides.get(0);
        List<Observation> observations = new ArrayList<>();
        for (S7Frame frame : S7Framer.frames(client.stream().contiguousPrefix()).frames()) {
            if (frame.rosctr() == 1) {
                observations.add(observationOf(client.stream(), frame));
            }
        }
        return new Decoded(observations, client, unread, false);
    }

    /** ModbusDecoder.observationOf 와 같은 모양이다 — 프로토콜과 매핑 함수만 다르다. */
    private static Observation observationOf(TcpStream stream, S7Frame frame) {
        return new Observation(
            stream.at(),
            new Endpoint(stream.sourceAddress(), stream.sourcePort()),
            new Endpoint(stream.targetAddress(), stream.targetPort()),
            Protocol.S7COMM,
            S7Access.of(frame.functionCode()),
            S7ObjectRef.of(frame.parameter()));   // 함수코드가 아니라 **파라미터 전체**를 넘긴다
    }
}
```

> **S1·S2·R1~R5 가 여기 없다.** 프레임이 스스로 요청임을 선언하므로 SYN 도 PDU 형태도 필요 없다. 1차가 신호 둘과 결합 규칙 다섯 줄로 하던 일을 필드 하나가 대신한다.

> **속도 주의.** 순회기는 모든 해독기의 `scan`을 모든 스트림에 돌리고 단축 평가를 하지 않는다. 151022의 대상 외 대화 93만 개가 이제 `S7Framer`도 통과하고, `ModbusDecoder`는 스트림당 최대 네 번(스캔 1 + 형태 신호 N + 클라이언트 1) 프레이밍한다. 1차의 2.6초 기준선보다 눈에 띄게 느려질 수 있다 — **멈춘 게 아니다.** 실제로 문제가 되면 그때 측정해서 다루고, 지금 미리 최적화하지 않는다.

- [x] **Step 5: 통과 확인** — `S7DecoderTest` `Tests run: 10, Failures: 0`

- [x] **Step 6: 커밋**

```bash
git add decode/src/main decode/src/test reconcile/src/main
git commit -m "feat: S7 해독기 — ROSCTR 이 방향을 선언하므로 신호 결합이 필요 없다"
```

---

### Task 9: 등록과 공존

**Files:**
- Modify: `decode/src/main/java/dev/krillin/huginn/decode/TrafficObserver.java` (`DECODERS` 에 `S7Decoder` 추가)
- Test: `decode/src/test/java/dev/krillin/huginn/decode/CoexistenceTest.java`

- [x] **Step 1: 실패하는 테스트 작성**

```java
@Test
void 한_캡처에_두_프로토콜이_섞여도_계수의_합이_전체_대화_수다() {
    // Modbus 대화 1 + S7 대화 1 + SSH 대화 1
    ObservationResult r = TrafficObserver.observe(List.of(modbusStream, s7Stream, sshStream));
    assertEquals(3, r.decodedConversations() + r.undecidableConversations() + r.skippedConversations());
    assertEquals(2, r.decodedConversations());
    assertEquals(1, r.skippedConversations());
}

@Test
void 두_프로토콜의_관찰이_한_목록에_섞여_나온다() {
    // 프로토콜별 분리는 하지 않는다(설계 §6) — 같은 칸에 센다.
    ObservationResult r = TrafficObserver.observe(List.of(modbusStream, s7Stream));

    assertEquals(2, r.observations().size());
    assertEquals(Set.of(Protocol.MODBUS_TCP, Protocol.S7COMM),
        r.observations().stream().map(Observation::protocol).collect(toSet()));
}

@Test
void 어떤_바이트열도_두_프레이머에_동시에_걸리지_않는다() {
    // 오프셋 0 의 바이트 2~3 은 MBAP 에선 프로토콜 ID(반드시 0), TPKT 에선 전체 길이(>= 7)다.
    // 두 프레이머가 **서로 모순되게** 제약하는 유일한 자리이므로 그 65,536 개 값을 전부 돌린다.
    //
    // 고정 프레임의 두 바이트만 덮어쓰면 나머지가 그 값에 대해 무효가 되어 사실상 두 경우만
    // 검사하게 된다. **값마다 나머지가 유효한 후보를 새로 만들어야** 시험이 된다.
    for (int value = 0; value <= 0xFFFF; value++) {
        // ① MBAP 후보 — protocolId 자리만 value 로 두고 나머지는 유효하게 유지한다.
        //    tid 를 0x0300 으로 잡아 앞 두 바이트가 TPKT 매직(03 00)과 같아지게 한다:
        //    동시 수용이 가능하다면 여기서 걸린다.
        byte[] mbap = ModbusFixtures.mbap(0x0300, 1, 3, ModbusFixtures.pdu(0, 2));
        mbap[2] = (byte) (value >>> 8);
        mbap[3] = (byte) value;
        assertFalse(claimedByBoth(mbap), "MBAP 후보 protocolId=0x" + Integer.toHexString(value));

        // ② S7 후보 — TPKT 길이가 **실제로** value 인 프레임을 만든다.
        //    전체 = 4(TPKT) + 3(COTP) + 10(S7 헤더) + 파라미터 → 파라미터 = value - 17.
        //    value < 18 이면 유효한 S7 프레임이 존재하지 않으므로 만들지 않는다.
        if (value >= 18) {
            byte[] parameter = new byte[value - 17];
            parameter[0] = 0x04;
            byte[] s7 = S7Fixtures.job(parameter);
            assertEquals(value, ((s7[2] & 0xFF) << 8) | (s7[3] & 0xFF), "픽스처가 길이를 맞췄는가");
            assertFalse(claimedByBoth(s7), "S7 후보 TPKT len=" + value);
        }
    }
}

// 후보가 최대 64KB 라 이 루프는 수 GB 를 할당했다 버린다. 10초 안팎 걸릴 수 있다 — 멈춘 게 아니다.

/** 두 **실제** 프레이머를 돌린다 — 수용 조건을 테스트가 재구현하면 사본을 검증하게 된다. */
private boolean claimedByBoth(byte[] candidate) {
    return !ModbusFramer.frames(candidate).frames().isEmpty()
        && !S7Framer.frames(candidate).frames().isEmpty();
}

@Test
void 한_대화의_두_방향이_서로_다른_해독기에_걸리면_등록_순서가_이긴다() {
    // 스트림 단위 불가능성은 대화 단위로 올라가지 못한다(설계 §3).
    // Modbus 가 먼저 등록돼 있으므로 반대 방향의 S7 Job 은 버려진다 — 그것을 고정한다.
    Diagnosed d = TrafficObserver.observeWithDiagnostics(
        List.of(modbusDirection, s7DirectionSameTuple), List.of(new ModbusDecoder(), new S7Decoder()));
    assertEquals(1, d.multiClaimConversations());
}
```

- [x] **Step 2: 실패 확인** → `DECODERS` 에 S7 이 없어 공존 테스트 실패

- [x] **Step 3: 등록**

```java
    private static final List<ProtocolDecoder> DECODERS =
        List.of(new ModbusDecoder(), new S7Decoder());
```

- [x] **Step 4: 통과 확인**

Run: `mvn test | grep -E "Tests run:|BUILD"`
Expected: `BUILD SUCCESS`. `CoexistenceTest` `Tests run: 4`. **기존 157건 + 신규 전부 통과이며 기존 테스트 파일은 여전히 무변경이다.**

Run: `git diff HEAD --stat -- decode/src/test/java/dev/krillin/huginn/decode/ModbusObserverTest.java cli/src/test`
Expected: 빈 출력

- [x] **Step 5: 커밋**

```bash
git add decode/src
git commit -m "feat: S7 해독기를 등록한다 — 계수 불변식은 구조로 지켜진다"
```

---

## Chunk 3: 실캡처 검증과 판정 기록

코드 산출물이 거의 없고 **측정과 기록**이 본체인 청크다. 청크 2에서 끊어도 의존이 깨지지 않는다.

**전제:** 캡처 세 개가 `samples/` 에 있어야 한다. 없으면 먼저 받는다:

```bash
bash scripts/fetch-samples.sh      # 또는  pwsh scripts/fetch-samples.ps1
```

### Task 10: 실캡처 회귀·진단 하네스

**Files:**
- Create: `decode/src/test/java/dev/krillin/huginn/decode/RealCaptureTest.java`

캡처는 저장소에 없으므로(라이선스) **환경변수가 가리킬 때만 도는 테스트**로 둔다. 테스트 소스는 §7의 측정 밖이라 이음매 예산을 쓰지 않는다. CLI에 `--only=` 같은 플래그를 다는 것은 `cli/src/main` 변경이라 §7을 넘긴다.

- [x] **Step 1: 테스트 작성**

```java
package dev.krillin.huginn.decode;

import dev.krillin.huginn.pcap.*;
import dev.krillin.huginn.reconcile.Access;      // undecidableCount 가 쓴다 — pcap 이 아니라 reconcile 이다
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * 4SICS 실캡처 회귀·진단. {@code HUGINN_SAMPLES} 가 캡처 디렉터리를 가리킬 때만 돈다 —
 * 캡처는 라이선스가 제각각이라 저장소에 넣지 않는다.
 *
 * <pre>
 * # PowerShell
 * $env:HUGINN_SAMPLES = "samples"
 * mvn -pl decode -am test -Dtest=RealCaptureTest -Dsurefire.failIfNoSpecifiedTests=false
 * </pre>
 */
@EnabledIfEnvironmentVariable(named = "HUGINN_SAMPLES", matches = ".+")
class RealCaptureTest {

    private static final List<String> CAPTURES = List.of(
        "4SICS-GeekLounge-151020.pcap",
        "4SICS-GeekLounge-151021.pcap",
        "4SICS-GeekLounge-151022.pcap");

    private static ObservationResult s7Only(String capture) throws Exception {
        return TrafficObserver.observe(streamsOf(capture), List.of(new S7Decoder()));
    }

    private static long undecidableCount(ObservationResult r) {
        return r.observations().stream().filter(o -> o.access() == Access.UNDECIDABLE).count();
    }

    /** 프레임에서 나온 관찰만 센다 — 순회기가 만든 관찰은 objectRef 가 "-" 다. */
    private static long frameObservations(ObservationResult r) {
        return r.observations().stream().filter(o -> !"-".equals(o.objectRef())).count();
    }

    private static List<TcpStream> streamsOf(String capture) throws Exception {
        Path path = Path.of(System.getenv("HUGINN_SAMPLES"), capture);
        return TcpStreamAssembler.assemble(
            FrameDecoder.decode(PcapReader.read(Files.readAllBytes(path))).segments());
    }

    @Test
    void Modbus_판정은_1차와_한_치도_다르지_않다() throws Exception {
        // S7 을 켜면 총계는 당연히 움직인다. Modbus 만 등록해 1차 기준선과 대조한다.
        ObservationResult r = TrafficObserver.observe(
            streamsOf("4SICS-GeekLounge-151022.pcap"), List.of(new ModbusDecoder()));

        assertEquals(56, r.decodedConversations());
        assertEquals(932_655, r.skippedConversations());
        assertEquals(24, r.undecidableConversations());
        assertEquals(48, undecidableCount(r), "UNDECIDABLE 관찰");
        assertEquals(49_767, r.observations().size(), "관찰 총수");
    }

    @Test
    void S7_프레임_관찰_수가_tshark_Job_수와_맞는다() throws Exception {
        // **총 관찰 수가 아니라 프레임에서 나온 관찰**을 센다. 순회기가 붙이는 꼬리·판정불가
        // 관찰은 objectRef 가 "-" 라 걸러진다. 설계 §8 이 "Job 수 = 관찰 수" 를 명시적으로
        // 부정하므로 총수로 단언하면 151021(Userdata 4건 → 꼬리)에서 반드시 틀린다.
        assertEquals(23_732, frameObservations(s7Only("4SICS-GeekLounge-151020.pcap")));
        assertEquals(86_403, frameObservations(s7Only("4SICS-GeekLounge-151021.pcap")));
        assertEquals(53_217, frameObservations(s7Only("4SICS-GeekLounge-151022.pcap")));
    }

    @Test
    void 총_관찰_수와_Job_수의_차이를_기록한다() throws Exception {
        // 총 관찰 = 프레임 관찰 + 꼬리 + 판정 불가. 이 차이는 정상이며 설계 §8 의 네 원인으로
        // 설명하는 대상이다. 단언하지 않고 찍어서 samples/README.md 로 옮긴다.
        for (String capture : CAPTURES) {
            ObservationResult r = s7Only(capture);
            System.out.printf("%s: 총 관찰 %d · 프레임 관찰 %d · UNDECIDABLE 관찰 %d · "
                    + "해독 대화 %d · UNDECIDABLE 대화 %d%n",
                capture, r.observations().size(), frameObservations(r), undecidableCount(r),
                r.decodedConversations(), r.undecidableConversations());
        }
    }

    @Test
    void 두_해독기가_한_대화를_주장하는_일은_없다() throws Exception {
        // 설계 §9 의 반증 조건. 0 이 아니면 등록 순서 규칙이 실제로 프레임을 버리고 있다.
        for (String capture : CAPTURES) {
            Diagnosed d = TrafficObserver.observeWithDiagnostics(
                streamsOf(capture), List.of(new ModbusDecoder(), new S7Decoder()));
            assertEquals(0, d.multiClaimConversations(), capture);
        }
    }

    @Test
    void 양방향_요청_대화_수를_기록한다() throws Exception {
        // 0 을 예상하지만 확인 전에는 모른다. **0 이 아닌 것은 반증이 아니라** Job 수와 관찰 수가
        // 벌어지는 정당한 원인이므로, 단언하지 않고 찍어서 samples/README.md 에 옮긴다.
        for (String capture : CAPTURES) {
            Diagnosed d = TrafficObserver.observeWithDiagnostics(
                streamsOf(capture), List.of(new ModbusDecoder(), new S7Decoder()));
            System.out.printf("%s: 양방향 요청 대화 %d%n", capture, d.bothDirectionRequestConversations());
        }
    }
}
```

> **기대값이 어긋나면 값부터 고치지 말고 원인을 찾는다.** 다만 어긋남에는 두 종류가 있다.
>
> - **총 관찰 수가 Job 수보다 큰 것은 정상**이다 — 꼬리·판정 불가 관찰이 더해진 것이다. 버그로 쫓지 않는다.
> - **`frameObservations`가 Job 수보다 작은 것도 정당할 수 있다.** 설계 §8의 네 원인 중 둘(양방향 요청 대화는 그 Job 을 하나도 관찰하지 않는다, tshark 는 TCP 를 재조립하지만 Huginn 은 `contiguousPrefix` 만 읽는다)이 이 방향으로 작용한다.
>
> 그러므로 순서는 이렇다 — 차이가 나면 **먼저 대화 단위로 원인을 규명한다.** 프레이밍이나 방향 판정 결함이면 고친다(설계 §9의 반증 조건). 위 두 정당한 원인으로 설명되면 **`samples/README.md`에 그 설명과 함께 기록하고, 단언을 측정값으로 낮추되 주석에 이유를 남긴다.** 설명 없이 숫자만 바꾸는 것이 금지된 것이지, 설명된 차이를 반영하는 것이 금지된 게 아니다.

- [x] **Step 2: 캡처 없이 도는지 확인 — 건너뛰어야 한다**

Run: `mvn -pl decode -am test | grep "Tests run:"`
Expected: `RealCaptureTest` 가 skip 되고 나머지는 그대로 통과. CI 에서 캡처 없이도 초록이다.

- [x] **Step 3: 캡처를 물려 실행**

Run (PowerShell):
```powershell
$env:HUGINN_SAMPLES = "samples"
mvn -pl decode -am test -Dtest=RealCaptureTest -Dsurefire.failIfNoSpecifiedTests=false
```

**`-Dsurefire.failIfNoSpecifiedTests=false` 가 없으면 실패한다** — `-am` 이 상류 모듈(`huginn-reconcile`)에도 필터를 적용하는데 거기엔 그 이름의 테스트가 없어 빌드가 깨진다.

Expected: 회귀·프레임 관찰·배타성 테스트 통과, 나머지 둘은 수치를 찍는다.

**Modbus 회귀가 깨지면 여기서 멈춘다.** 순회기를 뽑아내면서 Modbus 고유 로직을 함께 옮긴 것이므로, 원인을 찾기 전에는 다음으로 가지 않는다.

**S7 수가 어긋나면** 설계 §8의 네 원인 중 어느 것인지 대화 단위로 좁힌다 — 꼬리 `UNDECIDABLE`, 양방향 요청, tshark 의 TCP 재조립 대 `contiguousPrefix`, 다중 주장. 관찰은 4-tuple 을 들고 있으므로 엔드포인트 쌍으로 묶어 tshark 의 스트림별 Job 수와 맞춘다.

- [x] **Step 4: 커밋**

```bash
git add decode/src/test/java/dev/krillin/huginn/decode/RealCaptureTest.java
git commit -m "test: 실캡처 회귀·진단 하네스 — 캡처가 있을 때만 돈다"
```

---

### Task 11: 샘플 정책과 결과 재기록

**Files:**
- Modify: `samples/4SICS-GeekLounge-151020-policy.yaml`
- Modify: `samples/4SICS-GeekLounge-151021-policy.yaml`
- Modify: `samples/4SICS-GeekLounge-151022-policy.yaml`
- Modify: `samples/README.md`

S7을 켜면 세 캡처 모두 수치가 바뀐다. 지금 기록된 표는 갱신하지 않으면 **그냥 틀린 값**이 된다.

- [x] **Step 1: 관찰된 S7 통신을 확인한다**

Run:
```bash
tshark -r samples/4SICS-GeekLounge-151020.pcap -Y "s7comm.header.rosctr==1" \
       -T fields -e ip.src -e ip.dst | sort | uniq -c | sort -rn | head
```
세 캡처 모두에 대해 돌려 폴러와 PLC 를 확인한다.

- [x] **Step 2: 정책 파일에 S7 규칙을 넣는다**

**편집 의도는 1차와 같다 — 관찰된 통신 중 일부만 선언한다.** 1차의 151022 정책이 폴러 → PLC 세 대의 **읽기만** 선언해 쓰기가 위반으로 드러나게 한 것처럼, S7도 **폴러 → PLC 의 READ 만 선언하고 WRITE 는 선언하지 않는다.** 전부 선언하면 위반이 0건이라 대사가 실제로 도는지 알 수 없다.

151020·151021 은 지금 `peers: []` 이므로 실제 peer 를 채워 넣는다.

- [x] **Step 3: 세 캡처를 돌려 수치를 얻는다**

```bash
mvn -q -DskipTests package
chcp 65001    # 윈도 콘솔
for f in 151020 151021 151022; do
  java -Dstdout.encoding=UTF-8 -jar cli/target/huginn.jar \
       samples/4SICS-GeekLounge-$f.pcap samples/4SICS-GeekLounge-$f-policy.yaml
  echo "exit=$?"
done
```

- [x] **Step 4: 반증 조건 두 개를 실제로 측정한다**

설계 §8이 시험 방법까지 정해둔 것인데 앞 태스크의 어느 스텝도 이 수치를 만들지 않는다.

**① 1200SYM 표기 대조** — 렌더링 문자열이 아니라 **필드로** 맞춘다:

```bash
tshark -r samples/4SICS-GeekLounge-151020.pcap -Y "s7comm.header.rosctr==1"        -T fields -E occurrence=f -e s7comm.tiap.item.area1 -e s7comm.tiap.item.area2        -e s7comm.tiap.item.value | sort | uniq -c | head
```

Huginn 의 `objectRef` 분포와 맞춘다 — `area2` `0x0052` 와 LID 값이 `sym:m/<lid>` 의 `<lid>` 와 같아야 한다. 어긋나면 설계 §9의 네 번째 반증 조건이 발동한다.

**② 응답이 0건 관찰인지** — `RealCaptureTest`의 `frameObservations`가 tshark 의 ROSCTR 1 수와 정확히 같다는 것이 곧 이 증명이다(응답이 하나라도 관찰됐다면 그 수를 넘는다). 확인한 사실로 기록한다.

- [x] **Step 5: `samples/README.md` 를 다시 쓴다**

갱신할 것:
- 결과표 여섯 수치 — **갱신 후 값**으로
- 151022 의 위반 내역(1차의 "HIGH 20,980 · MEDIUM 48" 은 S7 분이 더해져 틀린 값이 된다)
- 독립 검증 표에 **S7 행 추가** — ROSCTR 1 대비 관찰 수, 응답 0건 관찰
- 판정 문단에 **151020 의 반전**을 적는다: 1차에서 "Modbus 가 한 프레임도 없다"고 기록한 캡처가 이제 2.3만 관찰을 낸다. 1차의 §10 판정("데이터셋의 Modbus 비중이 얇아 캡처 하나로만 시험됐다")이 **S7 을 붙이자 해소되었는지**를 여기서 다시 판정한다
- **여전히 미검증인 것**: S7ANY 주소 경로(실캡처 0건), `area1 != 0` 경로, CONTROL 계열(B단계), 비표준 포트 S7

- [x] **Step 6: 커밋**

```bash
git add samples
git commit -m "test: S7 을 켠 실캡처 결과를 다시 기록한다"
```

---

### Task 12: 이음매 판정

**Files:**
- Modify: `docs/superpowers/specs/2026-09-05-huginn-design.md` (1차 §10 — 네 번째 반증 조건 판정)
- Modify: `docs/superpowers/specs/2026-09-05-huginn-s7comm-design.md` (2차 §9 — 결과 기록)
- Modify: `README.md` (구조 표의 `decode` 행, 배지의 테스트 수)

- [x] **Step 1: 프로덕션 소스 변경을 센다**

Run:
```bash
git diff --stat $BASE..HEAD -- pcap/src/main contract/src/main reconcile/src/main cli/src/main
```

Expected(합격): 두 파일뿐이고 합계 4줄 안팎
```
 cli/src/main/java/dev/krillin/huginn/cli/Pipeline.java             | 6 +++---
 reconcile/src/main/java/dev/krillin/huginn/reconcile/Protocol.java | 2 +-
```

- [x] **Step 2: 판정을 기록한다 — 통과든 실패든**

1차 설계 §10 의 네 번째 조건 아래에 결과를 적는다. **넘었으면 무엇이 왜 바뀌어야 했는지 적는다** — 그게 세 번째 프로토콜을 붙일 사람에게 필요한 정보다. 통과했으면 실제 diff 를 인용해 적는다.

2차 설계 §9 에는 다섯 반증 조건의 결과를 각각 적는다:
- 프로덕션 소스 변경이 둘을 넘었는가
- S7 관찰 수 차이를 네 원인으로 설명했는가
- 1차 Modbus 판정이 움직였는가
- 1200SYM 표기가 tshark 의 `area2`·LID 필드와 맞는가
- 다중 주장 횟수가 0인가

- [x] **Step 3: `README.md` 갱신**

- 구조 표의 `decode/` 행: "Modbus/TCP → Observation" → "Modbus/TCP · S7comm → Observation"
- 테스트 배지 수 갱신
- "하지 않는 것" 표에서 **S7comm 행을 옮긴다** — 1차의 "1차에서 증명할 것은 프로토콜 개수가 아니다"는 이제 유효하지 않다. S7comm-plus·Userdata·CONTROL(B단계 전)로 대체한다
- 주장→테스트 표에 S7 행 추가

- [x] **Step 4: 기준 파일을 지우고 전체 검증**

```bash
rm .huginn-a-base      # Task 0 이 만든 로컬 파일. 남기면 워킹트리가 깨끗하지 않다
```

Run: `mvn test | grep -E "Tests run:|BUILD"`
Expected: `BUILD SUCCESS`

Run: `git status -sb`
Expected: 워킹트리 깨끗

- [x] **Step 5: 커밋**

```bash
git add docs README.md
git commit -m "docs: 이음매 판정 결과와 2차 README"
```

---

## 완료 조건

- [x] `mvn test` 전체 통과
- [x] **`ModbusObserverTest`·`EndToEndTest`·`ExamplePolicyTest` 가 한 줄도 고쳐지지 않았다**
      Run: `git diff --stat $BASE..HEAD -- decode/src/test/java/dev/krillin/huginn/decode/ModbusObserverTest.java cli/src/test` → Expected: 빈 출력
- [x] **프로덕션 소스 변경이 `Protocol` 상수 하나와 `Pipeline` 세 줄뿐이다** — 넘었으면 넘은 대로 기록했다
- [x] **`decode` 밖 어디에도 S7 지식이 없다**
      Run: `grep -rn "TPKT\|COTP\|ROSCTR\|rosctr\|0x32\|1200SYM\|S7Framer" --include=*.java pcap/src/main contract/src/main reconcile/src/main cli/src/main` → Expected: 히트 0건
- [x] `ObservationResult`·`Report`·`Huginn`·`contract/`·`pcap/` 이 바뀌지 않았다
- [x] **대화 계수 셋의 합이 전체 대화 수다** — 두 프로토콜이 섞인 캡처에서도
- [x] **응답(ROSCTR 2·3)이 0건 관찰이다** — 1차의 Modbus 응답 49,787건 불관찰과 같은 확인
- [x] **151022 의 Modbus 판정이 1차와 동일하다**(해독 56 · 대상 외 932,655 · UNDECIDABLE 대화 24 · 관찰 48 · 위반 21,028)
- [x] S7 관찰 수와 tshark Job 수의 차이를 **네 원인 중 무엇인지 대화 단위로 설명**했다
- [x] **어떤 바이트열도 두 프레이머에 동시에 걸리지 않는다** — 65,536 값 전수, 실제 프레이머로
- [x] 다중 주장 횟수를 세 캡처에서 측정해 기록했다
- [x] 세 정책 파일과 `samples/README.md` 가 갱신되어 기록된 수치가 실제와 맞는다
- [x] **1200SYM 표기를 tshark 의 `area2`·LID 필드와 대조했다** — 렌더링 문자열이 아니라 필드로
- [x] **빈 본문 테스트가 하나도 없다** — 단언 없는 테스트는 초록으로 통과하면서 아무것도 지키지 않는다
      Run: `grep -n "() {$" -A1 decode/src/test/java/dev/krillin/huginn/decode/S7*.java | grep -B1 "^\s*}$"` → Expected: 히트 0건
- [x] 1차 설계 §10 의 네 번째 조건과 2차 설계 §9 의 다섯 조건이 **전부 판정되어 기록**되었다
