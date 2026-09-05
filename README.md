# Huginn

![Java](https://img.shields.io/badge/Java-17-orange?logo=openjdk&logoColor=white)
![Build](https://img.shields.io/badge/build-Maven%20multi--module-blue)
![Tests](https://img.shields.io/badge/tests-239-brightgreen)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache_2.0-blue.svg)](LICENSE)

**[Yggdrasil](https://github.com/yggdrasil-iiot) IIoT 스파인의 관찰·대사 축 — 선언한 것과 실제로 오간 것을 맞춰 본다.** Modbus/TCP 와 S7comm 을 읽는다.

> **fail-closed 는 길목을 지나는 것만 막는다. Huginn 은 지나지 않은 것을 본다.**

Bifrost 는 *무엇이 OT/IT 경계를 넘을 수 있는지* 를 선언하고, 머지 전 게이트와 런타임 경계(Heimdall)가 그것을 강제한다. 그런데 엔지니어링 워크스테이션이 PLC 에 직접 붙거나, 미등록 장비가 물려 있거나, 우회 경로가 생기면 **그 길목을 아예 지나지 않으므로** 아무도 모른다. Huginn 은 pcap 을 읽어 실제 오간 Modbus/TCP 통신을 해독하고, **선언된 통신 정책과 대조해 미등록 통신을 찾는다.**

상용 OT 진단 도구는 baseline 을 트래픽에서 **학습**해야 한다 — 아무도 선언해두지 않았기 때문이다. Yggdrasil 계열에서는 **계약이 곧 화이트리스트**다. 시그니처도 이상탐지 모델도 필요 없고, 대조만 하면 된다.

```
선언(Bifrost) → 강제(게이트·Heimdall) → 관찰(Huginn) → 대사(Huginn)
  무엇이 허용        길목에서 막는다        실제로 무엇이     차이 = 우회
   되는가                                    오갔는가
```

## 쓰는 법

```bash
mvn -DskipTests package
java -jar cli/target/huginn.jar capture.pcap examples/policy.yaml
```

종료 코드는 **0** 위반 없음 · **1** 위반 있음 · **2** 사용법·입력·계약 오류다. `UNDECIDABLE` 이 아무리 많아도 위반이 0 이면 0 을 낸다 — 커버리지는 리포트가 항상 내므로 종료 코드까지 흐리지 않는다.

정책은 deny-by-default 다. 허용된 것만 적고, 적히지 않은 것은 전부 위반이다([`examples/policy.yaml`](examples/policy.yaml)):

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

리포트는 위반과 **커버리지 일곱 수치**를 함께 낸다. 커버리지가 없으면 "위반 0 건" 이 *깨끗하다* 는 뜻인지 *거의 못 읽었다* 는 뜻인지 알 수 없다.

```
Huginn — 통신 대사 결과
  처리 패킷              1,284
  대상 외 패킷             112
  해독한 대화                6
  대상 외 대화               3
  UNDECIDABLE 대화           1
  UNDECIDABLE 관찰           4
  미관측 바이트         85,525 (2.4%)

위반 1건
  [HIGH] 10.0.9.99:40000 → 10.0.2.11:502  MODBUS_TCP WRITE  holding:40001
           선언되지 않은 통신: 10.0.9.99:40000 → 10.0.2.11:502 MODBUS_TCP WRITE
```

> **윈도 콘솔에서는** 기본 코드페이지가 cp949 라 리포트의 한글이 깨진다. `chcp 65001` 로 바꾸고
> `java -Dstdout.encoding=UTF-8 -jar ...` 로 실행한다. 파일로 리다이렉트할 때도 같다.

`UNDECIDABLE` **대화**와 `UNDECIDABLE` **관찰**은 서로 다른 수다. 대화 쪽은 관찰을 하나도 만들지 못한 대화 수이고, 관찰 쪽은 판정 불가 대화가 낸 1 건에 더해 해독한 대화의 잔여 바이트·갭·절단·FC 43 을 포함한 전부다. 관찰 쪽을 빼면 FC 43 만 잔뜩 든 캡처가 "대화 전부 해독" 으로 보이고, 대화 쪽을 빼면 한 방향만 잡힌 캡처가 드러나지 않는다.

## 지키는 원칙 — 그리고 그것을 붙잡아 두는 테스트

| 주장 | 테스트 |
|---|---|
| 포트가 아니라 **프레이밍**으로 프로토콜을 판정한다 — 우회하는 사람은 포트를 바꾼다 | `ModbusFramerTest.protocolId가_0이_아니면_프레임이_아니다` · `EndToEndTest.포트가_502여도_프레이밍이_아니면_Modbus로_치지_않는다` |
| 포트가 아니라 **PDU 형태**로 방향을 판정한다 — 포트 휴리스틱은 거울상을 구별하지 못한다 | `ModbusObserverTest.서버_포트가_더_높아도_형태로_판정한다` · `클라이언트가_특권_포트를_바인딩해도_형태로_판정한다` |
| **요청만** 관찰한다 — 응답을 관찰하면 정상 통신이 전부 위반이 된다 | `ModbusObserverTest.요청만_Observation이_된다` |
| 한 방향만 잡힌 캡처는 요청으로 **단정하지 않는다** | `ModbusObserverTest.한_방향만_잡힌_캡처는_요청으로_단정하지_않는다` |
| SYN 과 PDU 형태가 어긋나면 어느 쪽도 믿지 않는다 | `ModbusObserverTest.SYN과_형태가_어긋나면_판정하지_않는다` |
| 모르는 것을 조용히 READ 로 치지 않는다 — FC 43 은 **MEI 14 만** READ 이고 MEI 13(읽기·쓰기 겸용)은 `UNDECIDABLE` | `ModbusAccessTest.장치식별_조회는_읽기다` · `CANopen_전송은_여전히_UNDECIDABLE이다` |
| 산업 프로토콜이 아닌 스트림은 `UNDECIDABLE` 이 아니라 **대상 외**다 | `EndToEndTest.비산업_트래픽은_UNDECIDABLE이_아니라_대상_외로_센다` |
| 대화 계수 셋의 합이 전체 대화 수다 — 어느 대화도 빠지거나 두 번 세이지 않는다 | `ModbusObserverTest.대화_수는_세_계수의_합과_같다` · `클라이언트_방향만_프레임을_못_뽑은_대화도_어딘가에_센다` |
| 같은 입력에 같은 리포트가 나온다 | `EndToEndTest.같은_입력에_같은_리포트가_나온다` |
| **갭 이후 구간은 잔여 0 으로 끝날 때만 받는다** — 중간부터 시작한 구간은 통째로 버린다 | `RunReaderTest.이후_구간은_잔여가_0일_때만_받는다` |
| **못 본 바이트를 리포트가 말한다** — 캡처에 없던 것과 해독 못 한 것의 합 | `EndToEndTest.리포트는_못_본_바이트를_비율과_함께_낸다` · `CoexistenceTest.산업_대화의_못_본_바이트를_센다` |
| **미등록 호스트의 PLC 정지·블록 다운로드가 HIGH 로 잡힌다** — S7 에서 가장 중요한 우회 신호 | `EndToEndTest.미등록_호스트가_PLC를_정지시키면_HIGH로_잡는다` · `블록_다운로드도_HIGH로_잡는다` |
| **S7 은 ROSCTR 이 방향을 선언하므로 신호 결합이 필요 없다** | `S7DecoderTest.응답만_잡힌_캡처는_판정하지_않는다` · `양쪽_방향에_모두_요청이_있으면_판정하지_않는다` |
| 비-S7 TPKT(COTP 연결 요청)는 소비하되 세지 않는다 — 멈추면 그 대화의 요청이 전부 사라진다 | `S7FramerTest.연결요청_뒤의_Job_을_정상적으로_뽑는다` |
| **어떤 바이트열도 두 프레이머에 동시에 걸리지 않는다** — 65,536 값 전수, 실제 프레이머로 | `CoexistenceTest.어떤_바이트열도_두_프레이머에_동시에_걸리지_않는다` |
| 두 프로토콜이 섞여도 대화 계수의 합이 전체 대화 수다 | `CoexistenceTest.한_캡처에_두_프로토콜이_섞여도_계수의_합이_전체_대화_수다` |
| 위반이 든 캡처에서 실제로 잡힌다 — 정상 캡처의 0 건만으로는 증명되지 않는다 | `EndToEndTest.미등록_장비의_쓰기를_잡는다` · `비표준_포트의_우회를_잡는다` |

## 하지 않는 것 — 그리고 그 이유

| 안 하는 것 | 이유 |
|---|---|
| **라이브 캡처** | 권한·환경 의존이 커서 테스트가 결정적이지 않다. 파서와 대사 로직이 같으므로 나중에 소스 어댑터로 붙인다 |
| **능동 스캔** | OT 에서는 스캔이 설비를 멈춘다. 수동 관찰이 원칙이다 |
| **자동 차단·교정** | 고치지 않고 **보고만 한다.** 자동 교정은 판정 로직이 틀렸을 때 피해를 증폭시킨다 |
| **OPC UA · Sparkplug 해독** | 거버넌스 경로 **자체**라 우회 탐지 대상이 아니다 |
| **S7comm 제어의 서브서비스 해석** | `0x28` 의 실제 동작은 가변길이 서비스 문자열에, 블록 함수의 대상은 파일명 형태 식별자에 있다. 실캡처가 없어 대조할 수 없으므로 읽지 않는다 — 통째로 CONTROL 로 올리며 **과대분류인 면을 인정한다** |
| **S7comm-plus** · **Userdata(ROSCTR 7) 해석** | 전자는 4SICS 세 캡처에 0 프레임, 후자는 전체 4 건이다. 검증할 데이터가 없다 |
| **갭 이후 구간의 재동기화** | 갭 이후 구간은 **엄격 적합**으로만 읽는다 — 오프셋 0 에서 시작해 잔여 0 으로 끝날 때만 받고, 경계를 찾아 스캔하지는 않는다. 중간부터 시작한 구간은 통째로 버리고 그 바이트를 리포트에 낸다 |
| **게이트웨이 뒤 유닛ID 단위 판정** | 정책이 IP 기준이라 시리얼 게이트웨이 경유 우회는 보이지 않는다. 유닛ID 를 정책에 넣으려면 계약 자체를 바꿔야 한다 |
| **재동기화** | 프레임 경계를 찾아 앞으로 스캔하지 않는다. 임의 바이너리를 Modbus 로 오인하면 미등록 쌍에서 HIGH 가 만들어진다 — 오탐이 오검출보다 비싸다 |
| **절대 성능 주장** | 로컬 측정으로는 증명되지 않는다 |

## 구조

```
pcap/       pcap 파일 → 패킷. 링크레이어·IPv4·TCP 스트림 재조립
decode/     Modbus/TCP · S7comm → Observation  ← 프로토콜 지식은 여기서 끝난다
contract/   CommunicationPolicy 읽기
reconcile/  관찰 ↔ 선언 대사 → Finding    ← 순수 로직. 입출력도 프로토콜 지식도 없다
cli/        진입점과 리포트
```

`pcap` · `decode` · `reconcile` 에는 런타임 서드파티 의존이 없다. YAML 을 읽는 `contract` 만 Jackson 을 쓴다.

```bash
mvn test
```

239 건 중 7 건은 4SICS 실캡처가 있을 때만 도는 회귀·진단 테스트다(`HUGINN_SAMPLES` 로 켠다).
캡처 없이는 건너뛰므로 기본 실행은 232 건이다 — `samples/README.md` 참조.

설계와 구현 계획은 [`docs/superpowers/`](docs/superpowers/) 아래에 있다.

## 라이선스

Apache-2.0 — [LICENSE](LICENSE)
