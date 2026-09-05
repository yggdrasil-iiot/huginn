# Huginn 2차 — S7comm 해독

- 상태: 초안 (2026-09-05)
- 선행: [1차 설계](2026-09-05-huginn-design.md) · 저장소 `yggdrasil-iiot/huginn` · Java 17 · Apache-2.0

---

## 1. 왜 만드는가

두 가지를 동시에 한다. **하나는 실용**이다 — 4SICS ICS Lab 캡처에서 산업 프로토콜의 압도적 다수가 S7comm이었고 Modbus는 캡처 하나에만 실려 있었다(1차 §10 판정). Modbus 단독으로는 우회를 볼 수 있는 현장이 좁다.

**다른 하나는 검증**이다. 1차 설계 §10의 네 번째 반증 조건이 이것을 겨냥한다:

> S7comm 을 붙일 때 `decode` 밖이 바뀌어야 하면 → `Observation` 이음매를 잘못 잡은 것이다

이 문서는 그 시험을 **통과하려고** 쓰는 것이 아니라 **판정하려고** 쓴다. 합격선을 §7에 미리 못박고, 결과가 어느 쪽이든 그대로 기록한다.

---

## 2. 범위

두 단계로 나눈다. 각 단계는 독립적으로 닫히며, A만 하고 멈춰도 이음매 판정은 끝난다.

### A단계 — Read/Write와 이음매

- TPKT → COTP → S7comm 3중 프레이밍
- `0x04` Read Var → `READ`, `0x05` Write Var → `WRITE`
- Modbus와 S7이 한 캡처에 섞였을 때의 대화 계수
- **실캡처(4SICS 3개)로 tshark 대조 검증**

### B단계 — CONTROL

- `0x28` PLC Control · `0x29` PLC Stop
- `0x1A`~`0x1F` 블록 다운로드/업로드 — 엔지니어링 워크스테이션이 PLC에 로직을 내려받는 경로이며, **S7에서 가장 중요한 우회 신호**다
- **합성 캡처로만 검증**한다. 4SICS에 이 트래픽이 없다

### 만들지 않는다 — 그리고 그 이유

| 제외 | 이유 |
|---|---|
| **S7comm-plus** (S7-1200/1500 네이티브) | 4SICS 세 캡처에 **0 프레임**이다. 프레임 구조가 완전히 다르고 문서화도 빈약해 작업량이 몇 배인데, 검증할 데이터가 없다 |
| **Userdata(ROSCTR 7) 서브함수 해석** | 요청/응답 구분이 파라미터 안쪽에 또 있고, 블록·보안·시간 서브함수마다 구조가 다르다. 4SICS 표본은 4건뿐이다. 해석하지 않고 `UNDECIDABLE`로 남긴다 |
| **COTP 분할 재조립** | EOT=0 조각을 잇는 것은 TCP 재조립을 한 층 더 쌓는 일이다. 1차가 재동기화를 거부한 것과 같은 판단으로, 분할이 보이면 그 지점부터 `UNDECIDABLE`이다 |
| **프로토콜별 커버리지 분리** | 리포트가 프로토콜별로 수치를 나누면 `Report`·`ObservationResult`가 바뀌어 이음매 시험이 흐려진다. **합산을 유지**하고, 분리는 판정이 끝난 뒤 별도 작업으로 붙인다 |
| **rack/slot 단위 정책** | COTP 연결 요청에 rack·slot이 실리지만, 정책 계약은 IP 기준이다. 계약을 바꾸면 이음매 시험의 전제가 무너진다 |

---

## 3. 구조

### 지금 `ModbusObserver` 안에 두 가지가 섞여 있다

**프로토콜과 무관한 것** — 4-tuple을 뒤집어 대화로 묶기, 어느 스트림에도 유효 프레임이 없으면 대상 외로 끝내기, 관찰 수에 따라 해독/`UNDECIDABLE`을 세는 종결 규칙, 그리고 잔여·갭·절단에 `UNDECIDABLE` 관찰을 덧붙이는 규칙.

**Modbus 고유의 것** — MBAP 프레이밍, S1(SYN)·S2(PDU 형태) 신호와 결합 규칙 R1~R5, 함수코드 매핑.

앞을 공용 순회기로 올리고 뒤를 인터페이스 뒤로 넣는다.

```
decode/
  TrafficObserver     대화 순회와 계수 — 프로토콜을 모른다. cli 의 진입점
  ProtocolDecoder     이음매. 프로토콜 지식은 전부 이 뒤에 있다
  modbus/             1차 코드가 그대로 옮겨간다 (ModbusFramer·ModbusShape·ModbusAccess·ModbusObjectRef)
  s7/                 S7Framer·S7Access·S7ObjectRef
```

### 이음매

```java
interface ProtocolDecoder {
    Protocol protocol();

    /** 이 스트림에서 이 프로토콜의 프레임이 몇 개 나오는가. 0 이면 이 스트림은 이 프로토콜이 아니다. */
    StreamEvidence scan(TcpStream stream);

    /** 대화에서 요청 관찰을 만든다. 방향 판정 방식은 프로토콜마다 달라 여기 안에 있다. */
    Decoded decode(List<StreamEvidence> conversation);
}

/** @param leftoverBytes 프레임 뒤에 해독하지 못한 바이트가 남았는가 */
record StreamEvidence(TcpStream stream, int frameCount, boolean leftoverBytes) { }

/**
 * @param requestObservations 요청 프레임에서 만든 관찰. 응답은 들어가지 않는다(1차 §5-⑤)
 * @param clientStream        요청을 보낸 방향. **null 이면 판정 불가**다
 */
record Decoded(List<Observation> requestObservations, TcpStream clientStream) { }
```

`StreamEvidence`가 프레임 자체를 노출하지 않는 것이 요점이다. 순회기는 **개수와 잔여 여부만** 알고, 프레임·함수코드·PDU 형태는 해독기 밖으로 나오지 않는다. 해독기가 두 번 프레이밍하는 비용은 있으나(스캔에서 한 번, 해독에서 한 번), 프로토콜 지식이 새는 것보다 낫다. 실측 기준 1차 파이프라인이 227만 패킷을 2.6초에 처리하므로 여유가 있다.

### 대화 하나를 처리하는 순서

1. 대화의 각 스트림에 모든 해독기의 `scan`을 돌린다
2. **프레임을 주장한 해독기가 0개면** → 대상 외. 절단·갭과 무관하게 여기서 끝낸다(1차 우선순위 규칙 그대로)
3. **2개 이상이면** → 모순이다. 한 대화가 Modbus이면서 S7일 수 없다. `UNDECIDABLE` 관찰 1건을 남기고 끝낸다
4. **정확히 1개면** 그 해독기의 `decode`를 부른다. 이후는 프로토콜과 무관한 1차 종결 규칙 그대로다:
   - `clientStream == null`(판정 불가) → `UNDECIDABLE` 관찰 1건, `undecidableConversations`++
   - 관찰이 0건 → `UNDECIDABLE` 관찰 1건, `undecidableConversations`++
   - 관찰이 1건 이상 → `decodedConversations`++, 그리고 클라이언트 방향에 잔여·갭·절단이 있으면 `UNDECIDABLE` 관찰을 **하나 더** 붙인다(대화 계수는 건드리지 않는다)

순회가 한 번뿐이므로 **"세 계수의 합 = 전체 대화 수"가 구조적으로 유지된다.** 1차에서 이 불변식은 규율로 지켜졌지만, 이제는 어긋날 자리가 없다.

---

## 4. S7 와이어 포맷 — 실측 근거

4SICS 캡처의 실제 바이트에서 확인한 것이다(추측이 아니다).

```
TPKT   03 00 <len:2>                     len 은 TPKT 헤더 4바이트를 포함한 전체 길이
COTP   <li:1> F0 <tpdu-nr|eot:1>         DT Data. eot = 최상위 비트
S7     32 <rosctr:1> <redundancy:2> <pdu-ref:2> <param-len:2> <data-len:2>
       (ROSCTR 2·3 은 오류 클래스·코드 2바이트가 더 붙어 헤더가 12바이트)
파라미터 <func:1> <item-count:1> <items...>
```

관찰된 Write Var 요청 한 건:

```
03 00 00 28 | 02 f0 80 | 32 01 0000 0203 0012 0005 | 05 01 12 0e b2 ff 0000 0052 ea2db0d9 40000010 | ff 03 0001 01
└ TPKT 40 ┘  └ COTP  ┘  └ S7 헤더: Job, param 18, data 5 ┘   └ Write Var, 항목 1개 ┘
```

**길이 정합성이 MBAP length 검사에 대응하는 반증 장치다.** `TPKT len == 4 + (li+1) + 헤더길이 + param-len + data-len`이 성립해야 유효 프레임이다. 어긋나면 그 지점부터 미해독이고 **재동기화하지 않는다**. 한 TCP 세그먼트에 TPKT가 여러 개 실리므로 MBAP처럼 반복해서 자른다.

**`0x32`까지 봐야 S7 프레임으로 센다.** TPKT/COTP는 ISO-on-TCP 일반 규약이라 S7 전용이 아니다. COTP 연결 설정(CR `0xE0`·CC `0xD0`)만 오간 대화를 S7으로 주장하면, 포트로 프로토콜을 단정하지 말자던 1차 §5-①을 다른 층에서 되풀이하는 것이다. 연결 설정 프레임은 **증거로 세지 않는다** — 그 대화는 대상 외로 떨어질 수 있고, 그게 정직하다.

---

## 5. 판정 모델

### 방향 — ROSCTR이 답한다

| ROSCTR | 뜻 | 처리 |
|---|---|---|
| 1 (Job) | 요청 | **관찰한다** |
| 2 (Ack) · 3 (Ack_Data) | 응답 | 관찰하지 않는다 (1차 §5-⑤) |
| 7 (Userdata) | 요청·응답 양쪽 | 해석하지 않는다 → 그 대화에 `UNDECIDABLE` 관찰 1건 |

**S1·S2·R1~R5가 S7 경로에 존재하지 않는다.** 프레임이 스스로 요청임을 선언하므로 SYN도, PDU 형태도, 신호 결합도 필요 없다. 응답만 잡힌 단방향 캡처에도 별도 가드(1차 R5)가 필요 없다 — 관찰이 0건이 되고 §3의 종결 규칙이 그 대화를 `UNDECIDABLE`로 센다.

남는 판정 불가는 하나다. **양쪽 방향에 모두 Job이 있으면** 한 4-tuple에 연결이 둘 묶였거나 재조립이 어긋난 것이므로 `clientStream = null`이다. 1차 S2의 "양쪽이 같은 형태면 모순"과 같은 판단이다.

### Access 매핑

| | 함수코드 | 단계 |
|---|---|---|
| **READ** | `0x04` Read Var | A |
| **WRITE** | `0x05` Write Var | A |
| **CONTROL** | `0x28` PLC Control · `0x29` PLC Stop · `0x1A` Request download · `0x1B` Download block · `0x1C` Download ended · `0x1D` Start upload · `0x1E` Upload · `0x1F` End upload | B |
| **UNDECIDABLE** | `0xF0` Setup Communication, 그 외 전부, ROSCTR 7 | A |

`0xF0`을 READ로 치지 않는다. 세션 설정이지 데이터 접근이 아니고, 무엇을 읽거나 쓰지 않았다. 1차가 FC 43을 `UNDECIDABLE`로 둔 것과 같은 판단이다 — **모르는 것을 아는 척하지 않는다.**

블록 다운로드를 CONTROL로 두는 것이 B단계의 핵심이다. PLC 정지는 눈에 띄지만, **로직을 조용히 바꾸고 가는 경로가 실제 위험**이다.

### objectRef

근거 표시용이며 판정에는 쓰지 않는다(1차와 동일). **관찰은 프레임당 하나**이고, 요청에 항목이 여럿이면(실캡처에 5개짜리가 있다) 첫 항목을 쓰고 개수를 덧붙인다 — 함수코드가 프레임 단위라 access는 모호해지지 않는다.

| 주소 형식 | 표기 | 검증 |
|---|---|---|
| **1200SYM** (syntax id `0xb2`) | `sym:m/16` — root area와 LID 값 | **실캡처.** 4SICS 세 캡처의 주소는 **100%가 이것**이다 |
| **S7ANY** (syntax id `0x10`) | `db1.dbx20.0` · `m20.0` — area·DB번호·비트주소 | **합성만.** 실캡처에 **0건**이다 |
| 그 외 syntax id, 또는 못 읽음 | `fc:<n>` | — |

교과서에 나오는 형식(S7ANY)이 실데이터에 하나도 없다는 사실이 이 표의 요점이다. 둘 다 다루되 **검증 강도가 다르다는 것을 문서와 `samples/README.md`에 적는다.**

---

## 6. 계수와 리포트

**바뀌지 않는다.** `ObservationResult`의 세 계수도, `Report`의 여섯 줄도 그대로다. S7 관찰은 Modbus 관찰과 같은 칸에 섞여 센다.

대가가 있다 — 99% S7인 캡처에서 Modbus가 얼마나 얇은지 리포트만 보고는 알 수 없다. 그것을 알고 감수한다. **이 단계의 목적은 이음매 판정이고, 리포트를 건드리면 판정이 흐려진다.** 프로토콜별 분리는 판정이 끝난 뒤 별도 작업이다.

---

## 7. 이음매 시험의 합격선

작업이 끝나면 `git diff --stat`으로 `decode` 밖 변경을 센다. **허용되는 것은 정확히 둘이다:**

1. `reconcile`의 `Protocol` 열거형에 `S7COMM` 상수 하나 — 1차 설계가 "이 열거형이 `reconcile`에 있는 것은 정책 계약이 프로토콜을 이름으로 선언하기 때문"이라고 이미 밝혀둔 자리다
2. `cli/Pipeline`의 import 1줄과 호출 1줄 — 진입점이 `ModbusObserver`에서 `TrafficObserver`로 바뀐다

이 둘 외에 `pcap`·`contract`·`reconcile`·`cli`가 한 줄이라도 바뀌면 **이음매를 잘못 잡은 것으로 판정하고 그대로 기록한다.** 무엇이 왜 바뀌어야 했는지가 다음 프로토콜을 붙일 사람에게 필요한 정보다.

---

## 8. 검증

### 실캡처 기대값 (tshark 4.6.8 대조)

A단계가 끝나면 아래와 정확히 맞아야 한다. tshark의 `-T fields`는 한 패킷의 여러 S7 PDU를 쉼표로 나열하므로 **PDU 단위 계수이고, Huginn의 프레임 단위 관찰과 같은 단위**다.

| 캡처 | S7 Job (= 관찰 수) | `0x04` → READ | `0x05` → WRITE | `0xF0` → UNDECIDABLE |
|---|---:|---:|---:|---:|
| 151020 | 23,732 | 23,709 | 23 | 0 |
| 151021 | 86,403 | 86,339 | 48 | 16 |
| 151022 | 53,217 | 53,196 | 14 | 7 |

**응답(ROSCTR 2·3)은 0건 관찰이어야 한다.** 1차에서 Modbus 응답 49,787건이 하나도 관찰되지 않은 것과 같은 확인이며, §5-⑤를 S7에서 다시 증명하는 자리다.

수치가 어긋나면 **원인을 적는다.** 1차에서 READ/WRITE 분류가 28건 갈린 것을 "TCP 세그먼트당 다중 프레임 계수 차이로 보인다"고 적고 끝냈는데, 같은 미결을 두 번 남기지 않는다.

### 회귀 가드

- **151022의 Modbus 판정이 위반 21,028건 그대로여야 한다.** 숫자가 움직이면 대화 순회를 뽑아내는 과정에서 무언가 깨진 것이다
- **`ModbusObserverTest` 20건과 `EndToEndTest` 11건을 한 줄도 고치지 않고 통과해야 한다.** 고쳐야 한다면 그것은 리팩터링이 아니라 동작 변경이다

### 새로 필요한 테스트

- Modbus 대화와 S7 대화가 한 캡처에 섞여도 세 계수의 합이 전체 대화 수다
- 두 해독기가 같은 대화를 주장하면 `UNDECIDABLE`이다
- TPKT 길이 정합성이 안 맞는 바이트를 S7으로 오인하지 않는다
- COTP 연결 설정(CR/CC)만 오간 대화는 S7으로 주장되지 않는다
- 양쪽 방향에 모두 Job이 있으면 판정 불가다
- ROSCTR 7만 실린 대화는 관찰 0건 → `UNDECIDABLE` 대화다

### B단계

합성 캡처로 검증하고 `samples/README.md`에 **"CONTROL 경로는 실캡처 미검증"** 을 1차의 비표준 포트 항목과 나란히 적는다. 픽스처는 `ModbusFixtures` 선례대로 `public`으로 두고 test-jar로 `cli` E2E와 공유한다.

---

## 9. 이 설계가 틀렸다고 판명되는 조건

- **`decode` 밖 변경이 §7의 둘을 넘으면** → `Observation` 이음매를 잘못 잡은 것이다. 1차 §10의 조건이 여기서 판정된다
- **S7 관찰 수가 tshark의 Job 수와 맞지 않으면** → 프레이밍이 틀린 것이다. 3중 프레이밍은 MBAP보다 실패할 자리가 많다
- **1차 Modbus 판정이 하나라도 움직이면** → 공용 순회기를 뽑아내면서 Modbus 고유 로직을 함께 옮긴 것이다
- **1200SYM 표기가 tshark의 해석과 어긋나면** → 주소 구조를 잘못 읽은 것이다. 근거 표시용이라 판정을 흔들지는 않지만, 운영자가 조치할 수 없는 근거는 없느니만 못하다
- **두 해독기가 같은 대화를 주장하는 일이 실캡처에서 흔하면** → 프레이밍 판정이 느슨한 것이다. 4SICS에서 몇 건 나오는지 세어 기록한다
