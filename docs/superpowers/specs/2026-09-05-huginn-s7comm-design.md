# Huginn 2차 — S7comm 해독

- 상태: **A단계 구현 완료** (2026-09-05). rev6 승인본 · 리뷰 5라운드 · 블로커 23건 반영
- 판정 결과는 §9 에 기록했다. 수치는 `samples/README.md`
- 선행: [1차 설계](2026-09-05-huginn-design.md) · 저장소 `yggdrasil-iiot/huginn` · Java 17 · Apache-2.0

---

## 1. 왜 만드는가

두 가지를 동시에 한다. **하나는 실용** — 4SICS ICS Lab 캡처에서 산업 프로토콜의 압도적 다수가 S7comm이었고 Modbus는 캡처 하나에만 실려 있었다(1차 §10 판정). Modbus 단독으로는 우회를 볼 수 있는 현장이 좁다.

**다른 하나는 검증.** 1차 설계 §10의 네 번째 반증 조건이 이것을 겨냥한다:

> S7comm 을 붙일 때 `decode` 밖이 바뀌어야 하면 → `Observation` 이음매를 잘못 잡은 것이다

이 문서는 그 시험을 **통과하려고** 쓰는 것이 아니라 **판정하려고** 쓴다. 합격선을 §7에 못박고, 결과가 어느 쪽이든 그대로 기록한다.

---

## 2. 범위

### A단계 — Read/Write와 이음매 (이 문서의 계획 대상)

- TPKT → COTP → S7comm 3중 프레이밍
- `0x04` Read Var → `READ`, `0x05` Write Var → `WRITE`
- `decode` 안을 프로토콜 중립 순회기와 `ProtocolDecoder` 이음매로 가르는 리팩터링
- Modbus와 S7이 한 캡처에 섞였을 때의 대화 계수
- **실캡처(4SICS 3개)로 tshark 대조 검증**

**A만으로 이음매 판정이 끝난다.** 구현 계획은 A단계까지만 쓰고, B는 판정 결과를 본 뒤 별도 계획으로 쓴다 — 한 계획이 리팩터링·새 프로토콜·실캡처 검증·합성 CONTROL 픽스처를 다 안으면 §7의 측정이 흐려진다.

### B단계 — CONTROL (후속, 별도 계획)

- `0x28` PLC Control · `0x29` PLC Stop
- `0x1A`~`0x1F` 블록 다운로드/업로드 — 엔지니어링 워크스테이션이 PLC에 로직을 내려받는 경로이며 **S7에서 가장 중요한 우회 신호**다
- 4SICS에 이 트래픽이 없어 **합성 캡처로만 검증**한다

### 만들지 않는다 — 그리고 그 이유

| 제외 | 이유 |
|---|---|
| **S7comm-plus** (S7-1200/1500 네이티브) | 4SICS 세 캡처에 **0 프레임**. 프레임 구조가 완전히 다르고 문서화도 빈약한데 검증할 데이터가 없다 |
| **Userdata(ROSCTR 7) 서브함수 해석** | 요청/응답 구분이 파라미터 안쪽에 또 있고 서브함수마다 구조가 다르다. **4SICS 전체에 4건**(전부 151021)이라 검증할 표본도 없다. 해석하지 않는다 — 처리 규칙은 §5 |
| **`0x28` PLC Control의 서브서비스 해석** | 실제 동작은 가변길이 서비스 문자열(`P_PROGRAM`·`_INSE`·`_DELE` 등)에 있다. 1차가 FC 8(Diagnostics)을 서브함수 해석 없이 통째로 CONTROL로 올린 것과 같은 보수적 판단이며, 같은 이유로 **과대분류인 면이 있다는 것을 인정한다** |
| **COTP 분할 재조립** | EOT=0 조각을 잇는 것은 TCP 재조립을 한 층 더 쌓는 일이다. 1차가 재동기화를 거부한 것과 같은 판단으로, 분할을 만나면 그 스트림은 거기서 자르기를 멈춘다. **어느 방향에서 보든 `Decoded.tailUndecidable`로 신호한다** — ROSCTR 7과 같은 이유다(서버 방향의 사건을 `client`만 보는 꼬리 규칙으로는 잡을 수 없다) |
| **프로토콜별 커버리지 분리** | 리포트가 프로토콜별로 수치를 나누면 `Report`·`ObservationResult`가 바뀌어 이음매 시험이 흐려진다. **합산을 유지**하고 분리는 판정 후 별도 작업 |
| **rack/slot 단위 정책** | COTP 연결 요청에 rack·slot이 실리지만 정책 계약은 IP 기준이다. 계약을 바꾸면 이음매 시험의 전제가 무너진다 |
| **Modbus FC 43의 MEI 타입 파싱** | 1차 §10이 "2차 작업 목록"으로 넘긴 항목이다. **여기서 다시 미룬다** — 그것을 하면 151021의 Modbus 판정 수치가 움직여 §8의 회귀 가드(1차 결과 불변)와 정면으로 충돌한다. 이음매 판정이 끝난 뒤 독립 작업으로 한다 |

---

## 3. 구조

### 지금 `ModbusObserver` 안에 두 가지가 섞여 있다

**프로토콜과 무관한 것** — 4-tuple을 뒤집어 대화로 묶기(등장 순서 유지), 어느 스트림에도 유효 프레임이 없으면 대상 외로 끝내기, 관찰 수에 따라 해독/`UNDECIDABLE`을 세는 종결 규칙, 잔여·갭·절단에 `UNDECIDABLE` 관찰을 덧붙이는 규칙.

**Modbus 고유의 것** — MBAP 프레이밍, S1(SYN)·S2(PDU 형태) 신호와 결합 규칙 R1~R5, 함수코드 매핑.

앞을 공용 순회기로 올리고 뒤를 인터페이스 뒤로 넣는다.

### 패키지는 평평하게 둔다

`modbus/`·`s7/` 하위 패키지로 나누지 **않는다.** `ModbusFixtures`가 `dev.krillin.huginn.decode`에 있고 `cli`의 `EndToEndTest`가 그 이름으로 import하므로, 옮기는 순간 §8의 "테스트를 한 줄도 고치지 않는다"가 깨진다.

```
decode/  TrafficObserver                 대화 순회와 계수 — 프로토콜을 모른다. cli 의 진입점
         ProtocolDecoder·StreamEvidence·Decoded   이음매. 프로토콜 지식은 전부 이 뒤에 있다
         ModbusDecoder                   ProtocolDecoder 구현. 1차 판정 로직을 그대로 감싼다
         ModbusObserver                  Modbus 전용 진입점(아래 참조)
         ModbusFramer·ModbusShape·ModbusAccess·ModbusObjectRef·ModbusFrame·FramingResult
         S7Decoder·S7Framer·S7Access·S7ObjectRef·S7Frame
         ObservationResult
```

main 소스가 9개에서 20개 안팎으로 는다. 그래도 평평하게 두는 이유는 위와 같다.

**`ModbusObserver.observe(List<TcpStream>)`는 공개 진입점으로 남는다.** `ModbusObserverTest` 20건이 이것을 부르고, 그 파일은 고치지 않기로 했다. 의미도 못박는다 — **Modbus 해독기 하나만** 등록해 순회기를 돌린다(`TrafficObserver.observe(streams, List.of(new ModbusDecoder()))`). 그 테스트가 증명하려는 것은 Modbus 판정이지 다중 프로토콜 공존이 아니다. 공존은 §8의 새 테스트가 따로 증명한다.

### 이음매

```java
interface ProtocolDecoder {
    Protocol protocol();

    /** 이 스트림에서 이 프로토콜의 프레임이 몇 개 나오는가. 0 이면 이 스트림은 이 프로토콜이 아니다. */
    StreamEvidence scan(TcpStream stream);

    /**
     * 대화에서 요청 관찰을 만든다. 방향 판정 방식은 프로토콜마다 다르므로 여기 안에 있다.
     * @param conversation 이 대화의 **모든** 스트림. frameCount == 0 인 것도 뺀 채로 주지 않는다 —
     *                     Modbus 의 R5(고른 방향이 캡처에 없음) 판정이 그 부재를 봐야 성립한다.
     *                     순서는 입력 목록에 처음 등장한 순서다.
     */
    Decoded decode(List<StreamEvidence> conversation);
}

/** @param leftoverBytes 프레임 뒤에 해독하지 못한 바이트가 남았는가 */
record StreamEvidence(TcpStream stream, int frameCount, boolean leftoverBytes) { }

/**
 * @param requestObservations 요청 프레임에서 만든 관찰. 응답은 들어가지 않는다(1차 §5-⑤)
 * @param client              요청을 보낸 방향의 **StreamEvidence**. null 이면 판정 불가다
 * @param tailUndecidable     프레임은 뽑았으나 해석하지 않은 것이 대화 어딘가에 있는가.
 *                            S7 이 Userdata(ROSCTR 7)나 COTP 분할을 만났을 때 세운다 — 그것들은
 *                            **응답 방향에도 실리므로** client 의 잔여만 보는 규칙으로는 잡히지 않는다.
 *                            Modbus 는 항상 false 다: 그쪽 잔여·갭·절단은 client 증거로 이미 흐른다
 * @param bothDirectionsRequested  client == null 인 이유가 **요청 방향이 둘**이어서인가.
 *                            0 개(응답만 잡힘·Userdata 만)와 2 개(한 4-tuple 에 연결이 둘)를
 *                            순회기는 구별할 수 없다 — 둘 다 frameCount > 0 이기 때문이다.
 *                            해독기만 아는 사실이므로 해독기가 싣는다. S7 은 Job 방향이 2 개일 때 세운다.
 *                            Modbus 는 R1 중 **양쪽이 REQUEST_ONLY** 인 경우에만 세운다 — R1 은
 *                            코드상 requestCount > 1 || responseCount > 1 이고, 양쪽이
 *                            RESPONSE_ONLY 인 쪽은 요청 방향이 **0 개**라 false 다.
 *                            client != null 이면 false
 */
record Decoded(List<Observation> requestObservations, StreamEvidence client,
               boolean tailUndecidable, boolean bothDirectionsRequested) { }
```

`Decoded`가 `TcpStream`이 아니라 `StreamEvidence`를 돌려주는 것이 중요하다. `TcpStream`은 `byte[] contiguousPrefix`를 컴포넌트로 가진 record라 **`equals`가 배열 참조 비교**다. 순회기가 클라이언트 스트림을 증거 목록에 되짚으려 하면 동일 인스턴스가 흐를 때만 우연히 동작한다. 증거를 그대로 돌려받으면 되짚을 일이 없다.

`StreamEvidence`가 프레임 자체를 노출하지 않는 것도 요점이다. 순회기는 개수·잔여 여부와 `TcpStream`의 `hasGap`·`truncated`만 보고, 프레임·함수코드·PDU 형태는 해독기 밖으로 나오지 않는다. 해독기가 두 번 프레이밍하는 비용은 있으나(스캔에서 한 번, 해독에서 한 번), 프로토콜 지식이 새는 것보다 낫다 — 1차 파이프라인이 227만 패킷을 2.6초에 처리하므로 여유가 있다.

### 해독기 등록과 선택

해독기 목록은 **`decode` 안에 고정 순서로** 둔다:

```java
public final class TrafficObserver {
    private static final List<ProtocolDecoder> DECODERS =
        List.of(new ModbusDecoder(), new S7Decoder());

    /** cli 가 부르는 유일한 판. */
    public static ObservationResult observe(List<TcpStream> streams) { return observe(streams, DECODERS); }

    /** ModbusObserver 와 테스트가 쓴다. */
    static ObservationResult observe(List<TcpStream> streams, List<ProtocolDecoder> decoders) { ... }

    /**
     * 진단까지 함께 낸다 — **테스트 전용**이다. ObservationResult 는 손대지 않는다(§6).
     * multiClaimConversations 는 한 대화에서 둘 이상이 주장한 횟수(§3)다.
     * bothDirectionRequestConversations 는 순회기가 **Decoded.bothDirectionsRequested 가 참인
     * 대화를 센 것**이며, 이긴 해독기를 가리지 않는 혼합 계수다(§8 참조).
     */
    static Diagnosed observeWithDiagnostics(List<TcpStream> streams, List<ProtocolDecoder> decoders) { ... }
}

record Diagnosed(ObservationResult result, int multiClaimConversations,
                 int bothDirectionRequestConversations) { }
```

`cli`는 첫 번째 판만 부르므로 `public`은 그것 하나로 족하다. 진단 판은 `decode` 테스트 소스에서만 부르고 `ObservationResult`도 리포트도 건드리지 않으므로 §7의 예산을 쓰지 않는다.

`cli`는 인자 없는 판만 부른다 — 목록을 알면 진입점 변경이 한 줄로 끝나지 않는다. 인자 있는 판은
`ModbusObserver`와 테스트가 쓴다.

대화 하나를 처리하는 순서:

1. 대화의 각 스트림에 모든 해독기의 `scan`을 돌린다
2. **프레임을 주장한 해독기가 없으면** → 대상 외. 절단·갭과 무관하게 여기서 끝낸다(1차 우선순위 규칙 그대로)
3. **주장한 해독기 중 등록 순서상 첫 번째**가 그 대화를 처리한다
4. 이후는 프로토콜과 무관한 1차 종결 규칙 그대로다. **아래 셋은 순서 있는 사슬이며 먼저 맞는 것이 이긴다** — 이 순서라야 계수 불변식이 성립한다:
   - `client == null`(판정 불가) → `UNDECIDABLE` 관찰 1건, `undecidableConversations`++. 이 관찰의 `at`·`source`·`target`은 **증거 목록의 첫 원소**(= 대화에 처음 등장한 스트림)에서 오고, `protocol`은 **이긴 해독기의 `protocol()`** 이다(순회기가 프로토콜을 지어낼 자리는 없다)
   - `requestObservations`가 비었으면 → `UNDECIDABLE` 관찰 1건, `undecidableConversations`++. 이 관찰은 **`client`의 `at`·`source`·`target`** 을 쓴다
   - 관찰이 1건 이상 → `decodedConversations`++, 그리고 **`client`에 잔여·갭·절단이 있거나 `Decoded.tailUndecidable`이 참이면** `UNDECIDABLE` 관찰을 **하나 더** 붙인다(대화 계수는 건드리지 않는다)

순회기가 만드는 `UNDECIDABLE` 관찰 셋은 모두 **`protocol` = 이긴 해독기의 `protocol()`, `objectRef` = `"-"`** 다(1차 `ModbusObserver.undecidableOf`와 같다). **세 번째(꼬리) 관찰의 `at`·`source`·`target`은 `client`의 것을 쓴다** — `tailUndecidable`이 서버 방향의 사건에서 비롯됐더라도 그렇다. 1차와 같은 선택이며, 근거 줄에 찍히는 주소가 구현자 재량이 되지 않게 한다.

순회가 한 번뿐이고 모든 분기가 정확히 하나의 계수를 올리므로 **"세 계수의 합 = 전체 대화 수"가 구조적으로 유지된다.**

**대화 순회 순서는 `LinkedHashMap`으로 최초 등장 순서를 유지한다.** 1차와 동일하며, `EndToEndTest.같은_입력에_같은_리포트가_나온다`가 이것에 의존한다.

### 충돌 분기를 두지 않는 이유

"두 해독기가 같은 대화를 주장하면 모순"이라는 분기를 rev1에 뒀다가 뺐다. 두 가지 이유다.

**첫째, 이 조합에서는 원리적으로 일어날 수 없다.** MBAP는 오프셋 0의 바이트 2~3(프로토콜 ID)이 `0x0000`이어야 하고, TPKT는 같은 자리가 전체 길이(최소 7)여야 한다. 두 조건은 동시에 참일 수 없고, **두 프레이머 모두 오프셋 0에서 자기 프레이밍이 성립해야 주장하므로**(재동기화하지 않는다) 한 스트림이 둘 다에 걸리지 않는다. S7 쪽은 오프셋 0의 프레임이 S7이 아니어도(§4의 CR 소비) 주장할 수 있지만, 그때도 **오프셋 0에 온전한 TPKT가 있어야 한다** — 바이트 2~3에 대한 모순은 그대로다.

**둘째, 그 분기는 만들 수 없는 관찰을 요구한다.** `Observation.protocol`은 필수인데 충돌한 대화는 어느 프로토콜도 아니다. `Protocol.UNKNOWN`을 추가하면 `reconcile`이 한 번 더 바뀌어, 이음매와 무관한 이유로 §7이 실패한다.

**다만 위 증명은 스트림 단위다.** 한 대화는 방향이 둘이므로, 한쪽이 Modbus로 다른 쪽이 S7으로 걸리는 배치를 증명이 배제하지 못한다(임시 포트 재사용으로 서로 다른 두 연결이 한 4-tuple에 묶이는 경우 — 1차가 이미 겪은 그 문제다). 그때 등록 순서로 Modbus가 이기면 **반대 방향의 S7 Job 은 조용히 버려진다.**

그래서 규칙은 **등록 순서상 첫 번째가 이긴다**로 두되, **한 대화에서 둘 이상이 주장한 횟수를 순회기가 세어 둔다.** 이 수는 리포트에 내지 않는다(§6의 합산 유지) — A단계 검증에서 **4SICS 세 캡처 모두 0인지 확인해 기록한다.** 0이 아니면 조용한 오판이 실제로 일어나고 있다는 뜻이고, §8의 관찰 수 차이를 설명하는 네 번째 원인이 된다.

스트림 단위 불가능성은 §8의 테스트로 고정한다. 세 번째 프로토콜을 붙일 때 이 전제가 무너지면 그때 다시 판단한다.

---

## 4. S7 와이어 포맷 — 실측 근거

4SICS 캡처의 실제 바이트에서 확인한 것이다(추측이 아니다).

```
TPKT   03 00 <len:2>                     len 은 TPKT 헤더 4바이트를 포함한 전체 길이
COTP   <li:1> F0 <tpdu-nr|eot:1>         DT Data. eot = 최상위 비트. COTP 헤더 길이 = li + 1
S7     32 <rosctr:1> <redundancy:2> <pdu-ref:2> <param-len:2> <data-len:2>
       (ROSCTR 2·3 은 오류 클래스·코드 2바이트가 더 붙어 헤더가 12바이트)
파라미터 <func:1> <item-count:1> <items...>
```

관찰된 Write Var 요청 한 건:

```
03 00 00 28 | 02 f0 80 | 32 01 0000 0203 0012 0005 | 05 01 12 0e b2 ff 0000 0052 ea2db0d9 40000010 | ff 03 0001 01
└ TPKT 40 ┘  └ COTP  ┘  └ S7 헤더: Job, param 18, data 5 ┘   └ Write Var, 항목 1개 ┘        └ 데이터 5 ┘
```

4 + 3 + 10 + 18 + 5 = 40 = TPKT `0x0028`.

**길이 정합성이 MBAP length 검사에 대응하는 반증 장치다.** `TPKT len == 4 + (li+1) + 헤더길이 + param-len + data-len`이 성립해야 유효 프레임이다. 어긋나면 그 지점부터 미해독이고 **재동기화하지 않는다**. 한 TCP 세그먼트에 TPKT가 여러 개 실리므로 MBAP처럼 반복해서 자른다.

**`0x32`까지 봐야 S7 프레임으로 센다.** TPKT/COTP는 ISO-on-TCP 일반 규약이라 S7 전용이 아니다. COTP 연결 설정(CR `0xE0`·CC `0xD0`)만 오간 대화를 S7으로 주장하면, 포트로 프로토콜을 단정하지 말자던 1차 §5-①을 다른 층에서 되풀이하는 것이다.

**비-S7 TPKT를 만나면 소비하고 계속 자른다 — 거기서 멈추지 않는다.** 이 규칙이 §8 기대값 표의 존폐를 가른다. 실제 클라이언트 스트림은 대개 **COTP 연결 요청(CR)으로 시작**하므로, 첫 비-S7 TPKT에서 멈추는 구현이면 `frameCount`가 0이 되어 그 대화가 통째로 대상 외로 떨어지고 **Job 2.3만·8.6만·5.3만 개가 전부 사라진다.**

- TPKT 길이가 정합하고 COTP 헤더가 온전하면, 그 프레임은 **소비**한다(오프셋을 TPKT 길이만큼 민다)
- 그 안의 페이로드가 `0x32`로 시작하지 않거나 COTP가 DT가 아니면 **`frameCount`에 세지 않고 `leftoverBytes`에도 넣지 않는다.** 미해독 바이트가 아니라 **우리 관심사가 아닌 프레임**이다. 세면 CR/CC만 오간 대화에 근거 없는 꼬리 `UNDECIDABLE`이 붙는다
- TPKT 길이 정합성이 깨지는 순간 거기서 멈추고 **남은 바이트 전부**를 `leftoverBytes`로 넘긴다

**이것은 재동기화가 아니다.** 재동기화는 경계를 *찾아* 앞으로 스캔하는 것이고, 여기서는 TPKT가 선언한 길이를 따라가는 것뿐이다. 1차가 거부한 것은 앞의 것이다.

연결 설정만 오간 대화는 `frameCount == 0`이라 **S7으로 주장되지 않는다** — 대상 외로 떨어지고, 그게 정직하다.

---

## 5. 판정 모델

### 방향 — ROSCTR이 답한다

| ROSCTR | 뜻 | 처리 |
|---|---|---|
| 1 (Job) | 요청 | **관찰한다** |
| 2 (Ack) · 3 (Ack_Data) | 응답 | 관찰하지 않는다 (1차 §5-⑤) |
| 7 (Userdata) | 요청·응답 양쪽 | **프레임으로는 세되 관찰하지 않는다** — 아래 |

**기본 규칙부터 쓴다 (예외만 적어두면 구현자가 추론해야 한다).** 한 대화에서 **Job 프레임을 실은 방향이 클라이언트**다. 그런 방향이 **0개거나 2개면 `client = null`**(판정 불가)이다. 0개인 경우가 응답만 잡힌 캡처와 Userdata만 실린 대화이고, 2개인 경우가 한 4-tuple에 연결이 둘 묶인 경우다 — 1차 S2의 "양쪽이 같은 형태면 모순"과 같은 판단이며, 그 대화의 Job은 **하나도 관찰되지 않는다**(§8의 계수 주의사항).

**ROSCTR 7 규칙 (한 곳에서만 정의한다).** Userdata 프레임은 유효 S7 프레임이므로 `frameCount`에 들어간다(그 스트림은 S7이지 대상 외가 아니다). 그러나 요청/응답을 가르지 않았으므로 관찰을 만들지 않고, **해독기가 `Decoded.tailUndecidable`을 세워** 그 대화에 `UNDECIDABLE` 관찰을 하나 붙인다. `StreamEvidence.leftoverBytes`로 신호하지 않는 이유는 두 가지다 — 그 필드의 뜻은 "프레임 뒤에 남은 바이트"이지 "해석하지 않은 프레임"이 아니고, **Userdata 응답은 서버 방향에 실리는데 순회기의 꼬리 규칙은 `client`만 본다.** 결과적으로:

- Userdata만 실린 대화 → Job 방향이 0개라 `client = null` → 관찰 0건 → **`UNDECIDABLE` 대화** 1개, 관찰 1건
- Job과 Userdata가 섞인 대화 → **해독한 대화**, 관찰은 Job 개수 + 꼬리 `UNDECIDABLE` **1건**(Userdata 프레임 수·방향과 무관하게 한 건)

이 규칙은 함수코드 매핑이 아니라 **프레임 단계의 규칙**이므로 아래 Access 표에 넣지 않는다.

**S1·S2·R1~R5가 S7 경로에 존재하지 않는다.** 프레임이 스스로 요청임을 선언하므로 SYN도, PDU 형태도, 신호 결합도 필요 없다. 응답만 잡힌 단방향 캡처에도 별도 가드(1차 R5)가 필요 없다 — 위 기본 규칙이 `client = null`을 내고 §3의 종결 규칙이 그 대화를 `UNDECIDABLE`로 센다. 1차가 신호 둘과 결합 규칙 다섯 줄로 하던 일을 **필드 하나가 대신한다.**

### Access 매핑

| | 함수코드 | 단계 |
|---|---|---|
| **READ** | `0x04` Read Var | A |
| **WRITE** | `0x05` Write Var | A |
| **CONTROL** | `0x28` PLC Control · `0x29` PLC Stop · `0x1A`~`0x1F` 블록 다운로드/업로드 | B |
| **UNDECIDABLE** | `0xF0` Setup Communication, 그 외 전부 | A |

`0xF0`을 READ로 치지 않는다. 세션 설정이지 데이터 접근이 아니고 무엇을 읽거나 쓰지 않았다. 1차가 FC 43을 `UNDECIDABLE`로 둔 것과 같은 판단 — **모르는 것을 아는 척하지 않는다.**

### objectRef

근거 표시용이며 판정에는 쓰지 않는다(1차와 동일). **관찰은 프레임당 하나**이고, 요청에 항목이 여럿이면 **첫 항목**을 쓰고 `(+N)`을 붙인다(N = 나머지 항목 수). 예: 항목 5개짜리 Read Var → `sym:m/16 (+4)`. 함수코드가 프레임 단위라 access는 모호해지지 않는다.

**1200SYM (syntax id `0xb2`) — 문법을 못박는다.**

```
항목:  12 <len:1> b2 <reserved:1> <area1:2> <area2:2> <crc:4> <lid:4>*
표기:  sym:<area>/<lid>[/<lid>...]
```

**LID 개수는 `<len>`에서 나온다** — `len`은 syntax id 부터 세므로 `(len - 10) / 4`개다(§4 예시의 `0x0e` → 1개). 이 계산 없이는 항목을 몇 바이트 읽을지 알 수 없다.

`<area>`는 **`area1`이 `0x0000`(IQMCT)일 때만** `area2` 코드에서 온다 — 실캡처에 나타난 값은 `0x0052` 하나뿐이고 이는 Flags(M)이므로 `m`으로 쓴다. **`area1`이 그 외 값이면 `area2`는 영역 코드가 아니라 DB 번호 계열이므로**(tshark가 `s7comm.tiap.item.dbnumber`를 따로 두는 이유다) 해석하지 않고 `sym:0x<area1>:0x<area2>/...` 원시 표기로 쓴다. 4SICS에는 `area1 != 0x0000`이 한 건도 없어 **그 경로는 실캡처로 검증되지 않는다.** `0x0052` 외의 `area2` 값도 이름을 지어내지 않고 `0x____`로 쓴다 — 지금 이름을 아는 코드는 그 하나뿐이다. `<lid>`는 각 LID 워드의 하위 28비트 값을 10진수로 쓴다(상위 4비트는 플래그다). §4의 예시 바이트 `... 0000 0052 ea2db0d9 40000010`은 `sym:m/16`이 된다. CRC는 표기에 넣지 않는다 — 주소가 아니라 심볼 무결성 값이다.

**S7ANY (syntax id `0x10`)** — `db<n>.dbx<byte>.<bit>` · `m<byte>.<bit>` 등 관례 표기. area 코드 `0x81`=I · `0x82`=Q · `0x83`=M · `0x84`=DB · `0x1C`=C · `0x1D`=T.

**그 외 syntax id이거나 항목을 못 읽으면** `fc:<n>` (1차 원칙 그대로).

| 형식 | 검증 강도 |
|---|---|
| 1200SYM | **실캡처.** 4SICS 세 캡처의 주소는 **100%가 이것**이다 |
| S7ANY | **합성만.** 실캡처에 **0건**이다 — 교과서 형식이 실데이터에 없다는 사실 자체를 기록한다 |

---

## 6. 계수와 리포트

**이 단계에서는 바뀌지 않는다.** `ObservationResult`의 세 계수도 `Report`의 여섯 줄도 그대로다. S7 관찰은 Modbus 관찰과 같은 칸에 섞여 센다. *(2026-09-05 후속 작업인 갭 이후 구간 처리가 일곱 번째 줄과 바이트 필드 둘을 더했다 — `samples/README.md` §④)*

대가가 있다 — 99% S7인 캡처에서 Modbus가 얼마나 얇은지 리포트만 보고는 알 수 없다. 알고 감수한다. **이 단계의 목적은 이음매 판정이고 리포트를 건드리면 판정이 흐려진다.** 프로토콜별 분리는 판정 후 별도 작업이다.

**샘플 산출물이 움직이는 것은 회귀가 아니라 예정된 결과다.** S7을 켜면 **세 캡처 모두** 수치가 바뀐다:

| 캡처 | 지금 | S7 을 켜면 |
|---|---|---|
| 151020 | 위반 0 · 종료 0 | 정책이 비어 있어 약 2.4만 건 위반 · 종료 1 |
| 151021 | 위반 0 · 종료 0 | 정책이 비어 있어 약 8.6만 건 위반 · 종료 1 |
| 151022 | 위반 21,028 (HIGH 20,980 · MEDIUM 48) · 종료 1 | S7 관찰 약 5.3만이 미선언으로 더해져 약 7.4만 건 · 종료 1 |

151022는 종료 코드가 그대로라 눈에 덜 띄지만 **위반 내역 표가 틀린 값이 된다.** A단계 작업에 **세 정책 파일 전부에 S7 규칙을 넣고 `samples/README.md` 결과표와 위반 내역을 다시 기록하는 일**을 포함한다.

**정책 편집 의도도 1차와 같게 둔다** — 관찰된 통신 중 **일부만** 선언한다. 1차의 151022 정책이 폴러 → PLC 세 대의 **읽기만** 선언해 쓰기가 위반으로 드러나게 한 것과 같이, S7도 **폴러 → PLC의 READ만 선언하고 WRITE는 선언하지 않는다.** 전부 선언하면 위반이 0건이라 대사가 실제로 도는지 알 수 없다.

`samples/README.md`에는 **갱신 후 수치**가 들어간다. 위 표는 "무엇이 왜 움직였는가"를 남기려고 적어둔 것이고, 결과표가 아니다.

---

## 7. 이음매 시험의 합격선

**측정 대상은 프로덕션 소스뿐이다** — `pcap/src/main`, `contract/src/main`, `reconcile/src/main`, `cli/src/main`. 문서(`README.md`·`docs/`)·샘플(`samples/`)·테스트 소스·빌드 파일은 제외한다. 그것들이 바뀌는 것은 새 프로토콜을 지원한 결과이지 이음매의 성질이 아니다.

**허용되는 변경은 정확히 둘이다:**

1. `reconcile`의 `Protocol` 열거형에 `S7COMM` 상수 하나 — 1차 설계가 "이 열거형이 `reconcile`에 있는 것은 정책 계약이 프로토콜을 이름으로 선언하기 때문"이라고 이미 밝혀둔 자리다. `contract`는 손대지 않아도 된다: `PolicyDocument.Rule.protocol`이 이 열거형 타입이라 YAML에서 `S7COMM`이 그대로 역직렬화된다
2. `cli/Pipeline.java` 한 파일 — 진입점이 `ModbusObserver`에서 `TrafficObserver`로 바뀌므로 import·호출·**클래스 javadoc의 이름 언급**까지 세 줄

이 둘 외에 프로덕션 소스가 한 줄이라도 바뀌면 **이음매를 잘못 잡은 것으로 판정하고 그대로 기록한다.** 무엇이 왜 바뀌어야 했는지가 다음 프로토콜을 붙일 사람에게 필요한 정보다.

측정 명령:

```bash
git diff --stat <A단계-시작-커밋>..HEAD -- pcap/src/main contract/src/main reconcile/src/main cli/src/main
```

---

## 8. 검증

### 실캡처 기대값 (tshark 4.6.8 대조)

```bash
tshark -r samples/4SICS-GeekLounge-<n>.pcap -Y "s7comm" \
       -T fields -e s7comm.header.rosctr -e s7comm.param.func
# 두 쉼표 목록을 같은 인덱스끼리 짝지어(zip) ROSCTR 1 인 PDU 의 func 만 센다
```

**`-Y`는 `-e`를 제한하지 않는다.** `-Y "rosctr==1"`로 거르고 `-e s7comm.param.func`만 뽑으면 통과한 패킷 안의 **Job 이 아닌 PDU 의 func 까지** 섞여 나온다. 두 필드를 함께 뽑아 인덱스로 짝지어야 한다.

짝짓기는 두 목록의 길이가 같을 때만 성립하므로 **줄마다 길이를 확인하고 다르면 세지 말고 실패시킨다.** 151021(Userdata 4건이 있는 유일한 캡처)에서 실측한 결과 **172,783줄 전부 길이가 일치했고**(불일치 0) Userdata 줄도 `func`를 냈다. 이 방식으로 다시 세어 아래 표를 검증했고 값은 rev2와 같았다.

`-T fields`는 한 패킷의 여러 S7 PDU를 쉼표로 나열하므로 위 명령은 **PDU 단위 계수**이며 Huginn의 프레임 단위와 같은 단위다.

| 캡처 | S7 Job 프레임 | `0x04` → READ | `0x05` → WRITE | `0xF0` → UNDECIDABLE |
|---|---:|---:|---:|---:|
| 151020 | 23,732 | 23,709 | 23 | 0 |
| 151021 | 86,403 | 86,339 | 48 | 16 |
| 151022 | 53,217 | 53,196 | 14 | 7 |

같은 명령으로 얻은 ROSCTR 전체 분포(응답이 0건 관찰인지 확인할 기준):

| 캡처 | 1 Job | 3 Ack_Data | 7 Userdata |
|---|---:|---:|---:|
| 151020 | 23,732 | 23,732 | 0 |
| 151021 | 86,403 | 86,402 | **4** |
| 151022 | 53,217 | 53,217 | 0 |

151021은 Job이 Ack_Data보다 하나 많다 — 캡처가 끝나며 응답을 못 받은 요청이 하나 있다. Userdata는 **4SICS 전체에 4건**이고 전부 151021이다.

**Job 프레임 수는 관찰 수와 같지 않다.** 네 가지가 벌어지게 한다:

- 해독한 대화에 잔여·갭·절단·Userdata가 있으면 `UNDECIDABLE` 관찰이 대화마다 **하나씩 더** 붙는다(관찰 수 > Job 수 방향)
- 양쪽 방향에 모두 Job이 있는 대화는 **Job을 하나도 관찰하지 않는다**(관찰 수 < Job 수 방향)
- **tshark는 기본적으로 TCP를 재조립하지만 Huginn은 `contiguousPrefix`만 읽고 재동기화하지 않는다** — 갭이 있는 스트림에서 tshark가 세는 PDU를 Huginn은 못 볼 수 있다
- **한 대화에서 두 해독기가 주장하면** 등록 순서로 진 쪽의 프레임이 통째로 버려진다(§3). 이 횟수를 세어 0인지 확인한다

그래서 검증은 **"Job 수 = 관찰 수"가 아니라** 이렇게 한다: Job 대비 관찰 수의 차이를 측정해 기록하고, **각 차이가 위 넷 중 어느 것인지 대화 단위로 설명한다.** 1차에서 READ/WRITE 28건 차이를 "다중 프레임 계수 차이로 보인다"고 적고 끝냈는데, 같은 미결을 두 번 남기지 않는다.

**측정 경로를 못박는다.** 리포트는 대화 단위 내역을 내지 않으므로(§6 동결) 아래처럼 나눈다:

| 측정할 것 | 어떻게 |
|---|---|
| S7 관찰 총수 | 151020·151021은 정책이 비어 있어 **CLI로 얻는다** — 관찰 총수 = 위반 + `UNDECIDABLE` 관찰 |
| Modbus 판정 불변(151022) | Modbus만 등록한 환경변수 회귀 테스트(아래) |
| 두 해독기가 한 대화를 주장한 횟수 | **둘 다 등록한** 두 번째 환경변수 테스트에서 `observeWithDiagnostics`로 읽는다 |
| 양쪽 방향에 모두 요청이 있는 대화 수 | 같은 진단 값(`bothDirectionRequestConversations`). **프로토콜 혼합 계수**다 — Modbus가 이긴 대화도 함께 세이므로, S7의 Job 차이를 설명할 때는 S7이 이긴 대화만 골라야 한다 |
| Job 수와 관찰 수의 차이를 대화 단위로 설명 | `Diagnosed`는 정수 둘과 평평한 관찰 목록만 낸다. 관찰은 4-tuple을 들고 있으므로 **엔드포인트 쌍으로 묶어** tshark의 스트림별 Job 수와 맞춘다. 프레임 수는 순회기 밖으로 나오지 않으므로 갭·절단 원인은 이 대조로 좁힌 뒤 해당 대화만 따로 들여다본다 |

**두 수치 모두 0일 것으로 예상하지만 확인 전에는 모른다.** 다만 둘의 무게가 다르다 — 다중 주장이 0이 아니면 §9의 반증 조건이 발동하지만, **양방향 요청 대화가 0이 아닌 것은 반증이 아니라** Job 수와 관찰 수가 벌어지는 정당한 원인(위 둘째 항목)이다. 세어서 차이를 설명하는 데 쓴다.

**응답(ROSCTR 2·3)은 0건 관찰이어야 한다.** 1차에서 Modbus 응답 49,787건이 하나도 관찰되지 않은 것과 같은 확인이며, §5-⑤를 S7에서 다시 증명하는 자리다.

### 회귀 가드

- **151022의 Modbus 판정이 위반 21,028건 그대로여야 한다.** 실측 기준선: 해독한 대화 56 · 대상 외 대화 932,655 · `UNDECIDABLE` 대화 24 · `UNDECIDABLE` 관찰 48.
  **대조 방법**: `decode` 테스트 소스에 환경변수로 켜지는 회귀 테스트를 둔다 — `HUGINN_SAMPLES`가 가리키는 디렉터리에 캡처가 있을 때만 돌고 없으면 건너뛴다(`@EnabledIfEnvironmentVariable`). 그 테스트는 `TrafficObserver.observe(streams, List.of(new ModbusDecoder()))`로 **Modbus만 등록해** 돌려 위 다섯 수치를 단언한다. 캡처는 저장소에 없고(라이선스) 테스트 소스는 §7의 측정 밖이라 이음매 예산을 쓰지 않는다. CLI에 `--only=` 같은 플래그를 다는 것은 `cli/src/main` 변경이라 §7을 넘긴다
- **`ModbusObserverTest` 20건과 `cli` 테스트 11건(`EndToEndTest` 10 + `ExamplePolicyTest` 1)을 한 줄도 고치지 않고 통과해야 한다.** 고쳐야 한다면 그것은 리팩터링이 아니라 동작 변경이다

### 새로 필요한 테스트

`S7Fixtures`(A단계에 필요하다 — `public final class`, 나중에 test-jar로 `cli`와 공유)로 다음을 고정한다:

- TPKT 길이 정합성이 안 맞는 바이트를 S7으로 오인하지 않는다
- COTP 연결 설정(CR/CC)만 오간 대화는 S7으로 주장되지 않는다
- 한 세그먼트에 TPKT가 여러 개일 때 전부 뽑는다
- ROSCTR 2·3은 관찰하지 않는다
- ROSCTR 7만 실린 대화는 관찰 0건 → `UNDECIDABLE` 대화 (§5 규칙)
- Job과 Userdata가 섞이면 해독한 대화 + 꼬리 `UNDECIDABLE` 관찰 1건
- 양쪽 방향에 모두 Job이 있으면 판정 불가다
- Modbus 대화와 S7 대화가 한 캡처에 섞여도 세 계수의 합이 전체 대화 수다
- **어떤 바이트열도 두 프레이머에 동시에 걸리지 않는다** — 예시 몇 개로 "증명"하지 않는다. 오프셋 0의 바이트 2~3이 두 프레이머가 **서로 모순되게** 제약하는 유일한 자리이므로(다른 자리도 각자 제약하지만 모순되지는 않는다), 그 **65,536개 값을 전부** 돌린다. 값마다 그 자리를 뺀 나머지가 유효한 MBAP 후보와 유효한 TPKT/COTP/S7 후보를 각각 만들어 **두 실제 프레이머를 그 위에 돌린다** — 테스트 안에서 수용 조건을 다시 구현하면 구현이 아니라 테스트의 사본을 검증하게 된다
- **한 대화의 두 방향이 서로 다른 해독기에 걸리면** 등록 순서로 하나가 이기고 다른 쪽 프레임이 버려진다는 것을 고정한다(§3). 실캡처에서 이 횟수가 0인지는 별도로 측정해 기록한다
- 1200SYM `sym:m/16` 표기가 §4의 실제 바이트에서 나온다

### 반증 조건의 시험 방법

§9의 "1200SYM 표기가 tshark 해석과 어긋나면"은 렌더링 문자열이 아니라 **필드로** 대조한다 — `s7comm.tiap.item.area2`와 `s7comm.tiap.item.value`(LID)를 뽑아 Huginn의 `sym:<area>/<lid>`와 맞춘다. tshark는 `sym:…` 모양을 출력하지 않으므로 문자열 비교는 시험이 될 수 없다.

---

## 9. 이 설계가 틀렸다고 판명되는 조건 — 그리고 판정 결과

> **A단계 판정 (2026-09-05): 다섯 조건 모두 반증되지 않았다.** 다만 넷째 항목에서 예상보다 큰
> 한계가 드러났고, 그것은 이 설계가 아니라 **1차의 재조립 정책**에 대한 발견이다.
>
> | 조건 | 결과 |
> |---|---|
> | 프로덕션 소스 변경이 §7 의 둘을 넘는가 | **아니오** — `Protocol` 1줄 + `Pipeline` 3줄, 정확히 예산대로 |
> | S7 관찰 수 차이를 네 원인으로 설명할 수 있는가 | **예** — 전량 세 번째 원인(`contiguousPrefix`)으로 귀속. 커버리지와 같은 자릿수·같은 방향이며 한 스트림이 지배한다(*"소수점 둘째 자리까지 일치" 라고 적었던 것은 정정했다 — 151020 은 9 배 차이다*). **후속 작업에서 해소되어 이제 tshark 와 정확히 일치한다** |
> | 1차 Modbus 판정이 움직였는가 | **아니오** — 151022 해독 56 · 대상 외 932,655 · UNDECIDABLE 대화 24 · 관찰 48 · 위반 21,028(HIGH 20,980 · MEDIUM 48) 전부 동일 |
> | 1200SYM 표기가 tshark 필드와 어긋나는가 | **아니오** — area1·area2·LID 가 개수까지 일치 |
> | 다중 주장 횟수가 0 이 아닌가 | **0 이다** — 세 캡처 모두. 대화 단위 충돌은 실제로 일어나지 않았다 |

### 조건 목록

- **프로덕션 소스 변경이 §7의 둘을 넘으면** → `Observation` 이음매를 잘못 잡은 것이다. 1차 §10의 조건이 여기서 판정된다
- **S7 관찰 수와 tshark Job 수의 차이를 §8의 네 원인으로 설명할 수 없으면** → 프레이밍이 틀린 것이다. 3중 프레이밍은 MBAP보다 실패할 자리가 많다
- **1차 Modbus 판정이 하나라도 움직이면** → 공용 순회기를 뽑아내면서 Modbus 고유 로직을 함께 옮긴 것이다
- **1200SYM 표기가 tshark의 `area2`·LID 필드와 어긋나면** → 주소 구조를 잘못 읽은 것이다. 근거 표시용이라 판정을 흔들지는 않지만, 운영자가 조치할 수 없는 근거는 없느니만 못하다
- **어떤 바이트열이 두 프레이머에 동시에 걸리면** → §3의 "충돌은 불가능하다"가 틀린 것이고, 등록 순서로 이기는 규칙이 조용한 오판이 된다
- **한 대화에서 두 해독기가 주장한 횟수가 4SICS에서 0이 아니면** → 스트림 단위 불가능성이 대화 단위로 올라가지 못한다는 뜻이며, 등록 순서 규칙이 실제로 프레임을 버리고 있다는 신호다
