# Huginn — 설계

- 상태: 승인됨 (2026-09-05)
- 저장소: `yggdrasil-iiot/huginn` · Java 17 · Maven 멀티모듈 · Apache-2.0

---

## 1. 왜 만드는가

Yggdrasil은 **무엇이 OT/IT 경계를 넘을 수 있는지**를 선언하고 강제한다. 강제 지점은 둘이다 — 머지 전 게이트(`gates` CLI)와 런타임 경계(Heimdall).

여기에 구조적 구멍이 있다.

> **fail-closed는 그 길목을 지나는 것만 막는다. 지나지 않는 것은 못 막는다.**

엔지니어링 워크스테이션이 PLC에 직접 붙거나, 미등록 장비가 물려 있거나, 우회 경로가 생기면 Bifrost는 아무것도 모른다. Yggdrasil에는 *"정말 아무것도 우회하지 않았는가"* 에 답할 수단이 없다.

Huginn은 그 답을 만든다. 신화에서 후긴과 무닌은 한 쌍이고, 오딘이 세상에 내보내면 **본 것을 보고하러 돌아온다.** Muninn(기억)이 UNS로 내보내는 쪽이라면 Huginn은 관찰하고 보고하는 쪽이다.

```
선언(Bifrost) → 강제(게이트·Heimdall) → 관찰(Huginn) → 대사(Huginn)
  무엇이 허용        길목에서 막는다        실제로 무엇이     차이 = 우회
   되는가                                    오갔는가
```

**상용 OT 진단 도구 대비 구조적 이점이 하나 있다.** 그들은 baseline 을 트래픽에서 **학습**해야 한다 — 아무도 선언해두지 않았기 때문이다. Yggdrasil 계열에서는 **계약이 곧 화이트리스트**다. 시그니처도 이상탐지 모델도 필요 없고, 대조만 하면 된다.

---

## 2. 범위

### 만든다

- **pcap 파일**을 읽어 **Modbus/TCP · S7comm** 대화를 해독한다
- 해독한 통신을 **선언된 통신 정책과 대조**해 **미등록 통신**을 찾는다
- 읽기·쓰기·제어를 구분한다 — 미등록 장비가 읽기만 한 것과 setpoint 를 쓴 것은 다른 사건이다

### 만들지 않는다 — 그리고 그 이유

| 제외 | 이유 |
|---|---|
| 라이브 캡처 | 권한·환경 의존이 커서 테스트가 결정적이지 않다. 파서와 대사 로직이 같으므로 나중에 소스 어댑터로 추가하면 된다 |
| 능동 스캔 | OT 에서는 스캔이 설비를 멈춘다. 수동 관찰이 원칙이다 |
| OPC UA · Sparkplug 해독 | **거버넌스 경로 자체**라 우회 탐지 대상이 아니다. 드리프트 대조용으로는 나중에 |
| 허용 범위 위반 · 명령 인가 위반 대조 | 이미 Heimdall 이 길목에서 막는 것의 사후 확인이라 중복이 크다. 값 의미론은 프로토콜·장비마다 달라 따로 파야 한다 |
| 자동 차단·교정 | **고치지 않고 보고만 한다.** 자동 교정은 판정 로직이 틀렸을 때 피해를 증폭시킨다 |
| 절대 성능 주장 | 로컬 측정으로는 증명되지 않는다 |

---

## 3. 아키텍처

```
huginn/
  pcap/       pcap 파일 → 패킷. 링크레이어·IPv4·TCP 스트림 재조립
  decode/     Modbus/TCP · S7comm → Observation
  contract/   CommunicationPolicy 읽기
  reconcile/  관찰 ↔ 선언 대사 → Finding
  cli/        진입점과 리포트
```

**Bifrost 의 모듈이 아니라 형제 앱이다.** Yggdrasil 의 기존 원칙이 그렇게 요구한다 — *apps share zero code; they compose only through the governed data/wire contract*. Huginn 은 Bifrost 내부를 읽지 않고 **내보내진 계약 파일만** 읽으며, 그래서 Bifrost 없이도 단독으로 테스트된다.

### 이음매 — `Observation`

```java
record Observation(
    Instant  at,          // pcap 패킷 시각
    Endpoint source,      // IP:port
    Endpoint target,
    Protocol protocol,    // MODBUS_TCP | S7COMM
    Access   access,      // READ | WRITE | CONTROL | UNDECIDABLE
    String   objectRef    // 건드린 주소·DB (프로토콜별로 정규화)
)
```

**프로토콜 지식은 `decode` 경계에서 끝난다.** 대사기는 Modbus 도 S7 도 모른다. 나중에 EtherNet/IP 를 얹어도 대사기는 바뀌지 않는다.

---

## 4. 계약 — `CommunicationPolicy`

Bifrost 는 장비 타입과 공정 명세를 선언하지만 **네트워크 토폴로지는 선언하지 않는다.** 그래서 Huginn 이 소비할 계약을 새로 정의한다. deny-by-default 이며 허용된 것만 적는다.

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
  - from: historian
    to: plc-mixer
    protocol: S7COMM
    access: [READ]          # 쓰기는 허용하지 않는다
```

**선언에 없으면 위반이다.** 초기에는 손으로 작성하고, Bifrost 가 이 파일을 내보내게 하는 것은 통합 단계의 일로 남긴다.

---

## 5. 판정 모델

### `Finding`

```java
record Finding(
    Severity    severity,   // 쓰기·제어가 읽기보다 높다
    Kind        kind,       // UNDECLARED_PEER | UNDECLARED_PROTOCOL | UNDECLARED_ACCESS
    Observation evidence,   // 무엇을 보고 그렇게 판단했는가
    String      detail
)
```

모든 Finding 은 **근거가 되는 관찰을 함께 들고 다닌다.** 근거 없는 경보는 운영자가 무시하게 된다.

### 지키는 원칙

**① 포트로 프로토콜을 단정하지 않는다.** 502=Modbus, 102=S7 은 관례일 뿐이고 **우회하는 사람은 포트를 바꾼다.** 포트는 힌트로만 쓰고 판정은 프레이밍 검증으로 한다(MBAP `protocolId=0`, TPKT `version=3`). 포트만 믿으면 비표준 포트의 우회를 놓치는데, 그것이 정확히 잡아야 할 대상이다.

**② 미해독 트래픽을 조용히 넘기지 않는다.** 디코더가 프레임을 못 읽으면 "정상" 으로도 "위반" 으로도 처리하지 않고 `UNDECIDABLE` 로 따로 센다. **파서가 모르는 것을 통과시키면 우회를 놓친다.**

**③ TCP 재조립에 갭이 있으면 그 대화는 그 지점부터 `UNDECIDABLE` 이다.** 조용히 이어붙이면 프레임 경계가 어긋나 엉뚱한 함수코드를 읽는다. 완전한 TCP 스택은 만들지 않는다 — seq 정렬과 갭 감지까지다.

**④ 모르는 함수코드는 `UNDECIDABLE` 이다.** 조용히 READ 로 치지 않는다.

### Access 매핑

| | READ | WRITE | CONTROL |
|---|---|---|---|
| Modbus/TCP | 1 · 2 · 3 · 4 | 5 · 6 · 15 · 16 · 22 · 23 | 8(진단) · 43(장치식별) |
| S7comm | 함수 4 (Read Var) | 함수 5 (Write Var) | `0x28` · `0x29` (PLC Start/Stop) |

---

## 6. 데이터 흐름

```
pcap 파일
  → PcapReader          글로벌 헤더 → 패킷 레코드 순회
  → LinkLayerDecoder    Ethernet → IPv4 → TCP
  → TcpStreamAssembler  4-tuple 단위 바이트 스트림, seq 정렬·갭 감지
  → FrameExtractor      Modbus: MBAP+PDU / S7: TPKT → COTP → S7 헤더
  → Decoder             함수코드 → Access
  → Reconciler          CommunicationPolicy 대조
  → Report
```

pcap 파싱은 **외부 의존 없이 직접 구현한다.** libpcap 바인딩을 쓰면 네이티브 의존이 생겨 테스트가 환경을 탄다. pcap 파일 포맷 자체는 단순하고(글로벌 헤더 + 패킷 헤더 + 링크레이어), 어차피 Modbus·S7 디코더는 직접 써야 하므로 그 아래 계층도 직접 쓰면 **의존성 0으로 결정적 테스트**가 된다.

---

## 7. 오류 처리 — 세 종류를 다르게

| 종류 | 처리 |
|---|---|
| **입력 오류** (깨진 pcap, 미지원 링크타입) | **즉시 실패.** 부분 결과를 내면 "위반 0건" 이 안전으로 오독된다 |
| **해독 실패** (알 수 없는 프레임 · 스트림 갭) | `UNDECIDABLE` 로 계수하고 계속 |
| **계약 오류** (선언 파일이 잘못됨) | **즉시 실패.** deny-by-default 라 계약이 틀리면 전부 위반으로 쏟아진다 |

> **"위반 0건" 과 "아무것도 못 읽었다" 를 구별할 수 없으면 이 도구는 위험하다.** 리포트 최상단에 항상 **처리 패킷 수 · 해독한 대화 수 · `UNDECIDABLE` 수**가 함께 나온다. 커버리지를 모르는 채로 깨끗하다고 말하지 않는다.

---

## 8. 테스트 전략

- **합성 pcap 을 코드로 조립**해 단위 테스트 — 외부 파일 의존 0, 완전히 결정적
- **위반이 든 캡처를 합성**해 실제로 잡히는지 확인 — *깨뜨렸을 때 잡히는지* 가 본 검증이다. 정상 입력에서 Finding 0건인 것만으로는 아무것도 증명되지 않는다(항상 빈 목록을 반환해도 통과한다)
- **잘린 프레임 · 갭 있는 스트림 · 비표준 포트**를 넣어 조용히 통과하지 않는지
- **결정성** — 같은 pcap 두 번에 같은 Finding 목록(순서 포함)
- **공개 ICS 캡처**로 통합 검증. **저장소에 넣지 않고** 다운로드 스크립트 + SHA-256 검증으로 둔다(라이선스가 제각각이다)

---

## 9. 나중으로 미룬 것

- 라이브 캡처 소스 어댑터
- OPC UA · Sparkplug 해독 → 거버넌스 경로의 **드리프트** 대조
- 허용 범위 위반(`MasterSpec`) · 명령 인가 위반(ACL) 대조
- Bifrost 가 `CommunicationPolicy` 를 내보내게 하는 통합
- EtherNet/IP 등 프로토콜 확장 (대사기는 바뀌지 않는다)

---

## 10. 이 설계가 틀렸다고 판명되는 조건

- 공개 ICS 캡처에서 `UNDECIDABLE` 비율이 압도적이면 → 두 프로토콜만으로 유의미한 판정이 된다고 본 전제가 틀린 것이다
- 실제 현장의 통신 조합이 손으로 선언할 수 없을 만큼 많으면 → `CommunicationPolicy` 를 사람이 쓴다는 전제가 틀린 것이고, Bifrost 연동이 선택이 아니라 필수가 된다
- 우회가 Modbus·S7 이 아니라 다른 경로로 주로 일어나면 → 프로토콜 선택이 틀린 것이다
