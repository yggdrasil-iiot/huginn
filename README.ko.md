# Huginn

![Java](https://img.shields.io/badge/Java-17-orange?logo=openjdk&logoColor=white)
![Build](https://img.shields.io/badge/build-Maven%20multi--module-blue)
![Tests](https://img.shields.io/badge/tests-313-brightgreen)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache_2.0-blue.svg)](LICENSE)

*English: [README.md](README.md)*

**[Yggdrasil](https://github.com/yggdrasil-iiot) IIoT 스파인의 관찰·대사 축 — 선언한 것과 실제로 오간 것을 맞춰 본다.** pcap 캡처에서 Modbus/TCP 와 S7comm 을 읽고, Zeek ICSNPP 로그에서는 S7comm-plus 까지 읽는다.

> **fail-closed 는 길목을 지나는 것만 막는다. Huginn 은 지나지 않은 것을 본다.**

Bifrost 는 *무엇이 OT/IT 경계를 넘을 수 있는지* 를 선언하고, 머지 전 게이트와 런타임 경계(Heimdall)가 그것을 강제한다. 그런데 엔지니어링 워크스테이션이 PLC 에 직접 붙거나, 미등록 장비가 물려 있거나, 우회 경로가 생기면 **그 길목을 아예 지나지 않으므로** 아무도 모른다. Huginn 은 pcap 을 읽어 실제 오간 산업 통신(Modbus/TCP · S7comm)을 해독하고, **선언된 통신 정책과 대조해 미등록 통신을 찾는다.**

상용 OT 모니터링은 "정상"을 트래픽 자체에서 끌어내야 한다. 대조할 선언이 없기 때문이다. **학습된** 행위 베이스라인이고, 대개 시그니처와 프로토콜 인지 규칙이 그 옆에 함께 선다. Yggdrasil 계열에서는 **계약이 곧 화이트리스트**라서 학습하는 대신 대조한다. 훈련할 모델도, 튜닝할 베이스라인도 없다.

```
선언(Bifrost) → 강제(게이트·Heimdall) → 관찰(Huginn) → 대사(Huginn)
  무엇이 허용        길목에서 막는다        실제로 무엇이     차이 = 우회
   되는가                                    오갔는가
```

## IEC 62443 의 언어로

62443 은 공장을 **존**과 그 사이의 **컨듀잇**으로 나눈다. 그리고 요구하는 건 한 번 그린
도면이 아니다. 지침은 **모든 통신 경로의 살아 있는 목록**(프로토콜·빈도·영향 자산·책임)을
유지하라고 하고, 감사인이 실제로 그 목록을 요구한다고 적는다. 지속 감시(SR 6.2)가 시스템
요구사항 쪽의 같은 이야기다.

**Huginn 은 그 목록의 관측된 절반을 만들고, 선언된 절반과 대조한다.** 산출물은 선언되지 않은
경로 하나당 한 줄이다 — 누가 누구에게, 어떤 프로토콜로, 무엇을 했고, 어떤 대상을 건드렸는지.

통상적인 방식과의 차이가 요점이다. 관행은 정상 트래픽을 **학습**해 베이스라인을 만들고
이탈을 알리는 것인데, 애초에 아무도 컨듀잇을 선언해두지 않았기 때문이다. 실제 제품에서는
시그니처와 프로토콜 인지 규칙이 그 베이스라인 옆에 함께 서지만, **학습**돼야 하는 부분은
베이스라인이고 선언이 대체하는 것도 그 부분이다. 여기서는 컨듀잇이 선언돼
있다. deny-by-default `CommunicationPolicy` 다. 그래서 Huginn 은 학습하지 않고 대조한다.
**훈련할 모델이 없고 드리프트할 베이스라인도 없다. 베이스라인 자체가 없기 때문이다.**
선언되지 않은 컨듀잇은 학습 기간이 지난 뒤가 아니라 첫 패킷에서 발견된다.

실제 컨듀잇 대장에 아직 못 미치는 것도 적어둔다. **빈도**(경로가 있다는 것은 말해도 얼마나
자주 쓰이는지는 아니다), **책임**(트래픽에서 도출되지 않는다. 선언 쪽에서 와야 한다), 그리고
해독하지 않는 프로토콜이 나르는 컨듀잇(열거되지 않고 대상 외로 세어진다). 이 갭들과 무엇이
그것을 강제하는지는 [Bifrost 의 `docs/ENTERPRISE.md` §5](https://github.com/yggdrasil-iiot/bifrost/blob/main/docs/ENTERPRISE.md#5-conduit-inventory) 에 있다.

이건 도구가 하는 일을 설명하는 방식이지 적합성 주장이 아니다. 인증은 없고, 62443-3-3 은
대장 하나보다 훨씬 많은 것을 요구한다.

## 쓰는 법

```bash
mvn -DskipTests package
java -jar cli/target/huginn.jar capture.pcap examples/policy.yaml
```

종료 코드는 **0** 위반 없음 · **1** 위반 있음 · **2** 사용법·입력·계약 오류다. `UNDECIDABLE` 이 아무리 많아도 위반이 0 이면 0 을 낸다 — 커버리지는 리포트가 항상 내므로 종료 코드까지 흐리지 않는다.

**정책은 어디서 오나.** 직접 쓴다 — 또는 Bifrost 가 거버넌스하는 장비에 한해 뽑아낸다: `gates conduit-project <registry> --edge <ip> --bind <장비>=<ip>` 가 바로 이 형식의 조각을 내고, 거버넌스 엣지만이 그 장비에 쓸 수 있다고 선언한다. Huginn 은 그걸 그대로 읽는다(Huginn 코드는 Bifrost 의 존재를 모른다 — 건너오는 건 파일 하나뿐이다). 그 조각의 헤더가 스스로 말하는 두 가지를 여기서도 되풀이한다: 장비↔주소 결속은 와이어에서 발견된 게 아니라 **사람이 선언한 것**이고, 이건 **조각**이다 — 누가 *쓸* 수 있는지만 말하지 누가 정당하게 *읽는지*는 모르므로, 단독으로 돌리지 말고 현장 정책에 합쳐라. 그러면 다른 호스트가 거버넌스 장비에 쓰는 것이, 엣지가 말하지도 않는 프로토콜로 들어오더라도, 이 도구가 찾으라고 있는 바로 그 우회로 잡힌다. Bifrost 의 [`run-huginn-seam-gate.sh`](https://github.com/yggdrasil-iiot/bifrost/blob/main/scripts/run-huginn-seam-gate.sh) 가 4SICS 캡처로 끝까지 증명한다.

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

리포트는 위반과 **커버리지 일곱 수치**, 그리고 **프로토콜별 표**를 함께 낸다. 커버리지가 없으면 "위반 0 건" 이 *깨끗하다* 는 뜻인지 *거의 못 읽었다* 는 뜻인지 알 수 없다.

```
Huginn — 통신 대사 결과
  처리 패킷              1,284
  대상 외 패킷             112
  해독한 대화                6
  대상 외 대화               3
  UNDECIDABLE 대화           1
  UNDECIDABLE 관찰           4
  미관측 바이트         85,525 (2.4%)

  프로토콜        해독 대화  UNDEC 대화        관찰  UNDEC 관찰       미관측 바이트
  MODBUS_TCP             0           0           0           0           0 (0.0%)
  S7COMM                 2           0      23,733           1      85,525 (2.4%)

위반 1건
  [HIGH] 10.0.9.99:40000 → 10.0.2.11:502  MODBUS_TCP WRITE  holding:40001
           선언되지 않은 통신: 10.0.9.99:40000 → 10.0.2.11:502 MODBUS_TCP WRITE
```

> **윈도 콘솔에서는** 기본 코드페이지가 cp949 라 리포트의 한글이 깨진다. `chcp 65001` 로 바꾸고
> `java -Dstdout.encoding=UTF-8 -jar ...` 로 실행한다. 파일로 리다이렉트할 때도 같다.

`UNDECIDABLE` **대화**와 `UNDECIDABLE` **관찰**은 서로 다른 수다. 대화 쪽은 관찰을 하나도 만들지 못한 대화 수이고, 관찰 쪽은 판정 불가 대화가 낸 1 건에 더해 해독한 대화의 잔여 바이트·갭·절단·FC 43 을 포함한 전부다. 관찰 쪽을 빼면 FC 43 만 잔뜩 든 캡처가 "대화 전부 해독" 으로 보이고, 대화 쪽을 빼면 한 방향만 잡힌 캡처가 드러나지 않는다.

### Zeek ICSNPP 로그로 읽기

```bash
java -jar cli/target/huginn.jar --zeek-log s7comm.log --zeek-log s7comm_plus.log --zeek-log modbus_detailed.log policy.yaml
```

OT 모니터링 환경 상당수가 이미 Zeek 과 ICSNPP 를 돌린다(Malcolm, Security Onion 등). 그래서 Huginn 은 파서를 더하지 않고 현장이 이미 만드는 로그를 읽는다. 가장 큰 이득은 Huginn 자체 디코더가 해독하지 못하는 **S7comm-plus**(최신 S7-1200/1500 펌웨어의 프로토콜)를 `s7comm_plus.log` 로 관찰한다는 점이다. 자체 디코더는 그대로이고, 정책 대사도 같은 `Reconciler` 가 한다.

- `--zeek-log <파일>` 쌍을 하나 이상 주고 마지막 인자로 정책을 준다. 기존 `huginn <capture.pcap> <policy.yaml>` 형식도 종료 코드도 그대로다.
- 디렉터리는 받지 않는다. 읽을 파일을 사용자가 정해야 로테이션된 사본이나 겹치는 내보내기를 두 번 세지 않는다. 같은 파일을 두 번 주면 거부한다(종료 코드 2).
- 파일은 이름이 아니라 `#path` 헤더(`s7comm`, `s7comm_plus`, `modbus_detailed`)로 알아본다. 다른 `#path` 는 거부한다(종료 코드 2). Zeek 의 ASCII TSV 형식만 읽고, JSON-lines 로그는 Zeek 을 `LogAscii::use_json=F`(기본값)로 돌리라는 메시지와 함께 거부한다.
- 헤더 선언(`#separator`, `#unset_field`, `#empty_field`)은 가정하지 않고 선언대로 따른다. 열은 이름으로 읽으므로 순서가 바뀌거나 열이 더 있어도 된다. Huginn 이 쓰는 열이 빠지거나 그 열의 `#types` 가 바뀌면 열 이름을 밝히고 거부한다(종료 코드 2).
- 고정 버전(ICSNPP 는 태그 릴리스가 없다): cisagov/icsnpp-s7comm `102a35c`(2026-10-22), cisagov/icsnpp-modbus `6dd3dab`(2026-10-17), Zeek 9.0.1.

정책에는 `S7COMM` 과 따로 **`S7COMM_PLUS`** 라는 프로토콜 이름이 생겼다. 둘을 합치면 S7-300 을 위해 쓴 `S7COMM: [READ]` 규칙이 S7-1500 으로 가는 S7comm-plus 읽기까지 조용히 허용한다. 정책은 `version: 1` 그대로라 기존 정책은 바꾸지 않아도 읽힌다. Bifrost 의 정책 조각 생성은 계속 `S7COMM` 을 내고, Bifrost 쪽은 바뀐 것이 없다.

pcap 경로와 마찬가지로 요청만 관찰이 된다.

- `s7comm.log`: ROSCTR 1(Job)이 요청이고 ROSCTR 2·3 은 응답이다. 종단은 `id.orig_*` 가 아니라 ICSNPP 의 실제 송신자 열 `source_h/source_p → destination_h/destination_p` 에서 읽는다. 접근 판정은 pcap 경로와 같은 `S7Access` 표를 쓴다. 로그에는 변수 주소가 없으므로 `objectRef` 는 읽기·쓰기가 `fc:4` / `fc:5`, 제어 함수는 기존 제어 이름(`plc-stop`, `upload-start` …)이고, PLC Control 은 ICSNPP 가 기록한 서비스 이름을 붙인다(예: `plc-control (PLC Start / Stop)`). User-Data(ROSCTR 7) 요청(함수 `0x4X`)은 pcap 경로도 해석하지 않으므로 `userdata:Request: CPU Functions/Read SZL` 같은 `objectRef` 를 단 `UNDECIDABLE` 이 되고, `0x8X` 는 응답이다.
- `s7comm_plus.log`: opcode `0x31`(Request)만 관찰한다. `0x32` 응답과 PLC 가 보내는 `0x33` 알림은 관찰하지 않는다. `decode` 의 새 `S7PlusAccess` 표는 READ = Get Multi Variables `0x054c` · Get Variable Sub Streamed `0x0586` · Explore `0x04bb`, WRITE = Set Variable `0x04f2` · Set Multi Variables `0x0542`, UNDECIDABLE = Create Object `0x04ca`(모든 세션의 첫 메시지이기도 하다) · Delete Object `0x04d4` · Begin Sequence `0x0556` · End Sequence `0x0560` · Invoke `0x056b` · Get Link `0x0524` 다. WRITE 는 하한이다 — S7-1200/1500 의 CPU 운전·정지도 CPU 객체에 대한 Set Variable 로 오가는데, 로그에는 객체 ID 가 없어 둘을 가를 수 없다. `objectRef` 는 `fn:<함수 이름>`(예: `fn:Set Variable`)이다.
- `modbus_detailed.log`: 한 행은 패킷이 아니라 트랜잭션이다. ICSNPP 가 트랜잭션 ID 로 요청과 응답을 짝짓는다. 방향 열이 없고 출발지는 `id.orig_*` 다. `matched=T` 는 요청을 봤다는 뜻이므로 관찰 1 건이다. `matched=F` 이면서 요청 열(`address`, `quantity`, `request_values`, `request_subfunction_code`, `request_data`)이 있으면 요청만 있는 행이므로 관찰 1 건, 없으면 방향 미확정이다. ICSNPP 가 따로 다루지 않는 함수(FC 7, 11, 12, 17 …)는 메시지마다 헤더만 든 행 하나를 남긴다. 연결·트랜잭션 ID·함수가 같은 연속 두 행이 요청 1 건이고, 홀로 남은 행은 방향 미확정이다. 짝 없는 예외 응답도 방향 미확정이다. 함수 이름은 Zeek 자체의 `Modbus::function_codes` 표로 코드에 대응시킨 뒤 pcap 경로와 같은 `ModbusAccess` / `ModbusObjectRef` 를 쓰므로 `holding:40001` 표기가 같다. FC 43 은 `mei_type` 이 정확히 `Read Device Identification` 일 때만 READ 다. 로그에는 FC 23 주소와 Read Device ID 코드가 없어 `fc:23` / `fc:43` 으로 나온다.
- 방향을 정할 수 없는 행으로는 관찰을 지어내지 않고 **연결마다 `UNDECIDABLE` 하나**를 남긴다. pcap 경로에서 한 방향만 잡힌 대화가 가는 자리와 같다.

위반은 pcap 과 똑같이 나열한다. 커버리지는 다르다 — 로그에는 패킷·바이트·대화 수가 없어서 리포트도 내지 않는다. 대신 모든 행의 행방을 낸다: 행 = 요청 행 + 응답·알림 행 + 방향 미확정 행. ICSNPP `s7comm_plus.pcap` 트레이스의 로그를, 두 프로토콜을 모두 선언하고 읽은 결과다.

```
Huginn — 통신 대사 결과 (Zeek 로그)
  읽은 로그 파일             2
  읽은 행                  155
  요청 행                   51
  응답·알림 행             104
  방향 미확정 행             0
  관찰                      51
  UNDECIDABLE 관찰           1
  패킷·바이트 커버리지 없음 — 로그에 없는 통신은 이 수에도 없다

  로그             프로토콜               행       요청  응답·알림     미확정       관찰  UNDEC 관찰
  s7comm           S7COMM               34         17         17          0         17           1
  s7comm_plus      S7COMM_PLUS         121         34         87          0         34           0

위반 없음
```

로그 경로는 로그에 있는 것을 판정한다. ICSNPP 트레이스에서는 판정한 요청(READ/WRITE/CONTROL)이 두 경로에서 같고, 차이는 타임스탬프·`UNDECIDABLE`·로그가 담지 않는 대상 표기뿐이다. 4SICS 캡처에서는 로그에 남은 요청이 와이어보다 적다 — 151020 은 6.6 시간 연결 중 처음 50 분 남짓 뒤로 `s7comm.log` 가 거의 끊기고, 151021 은 Read Device Identification 요청 5 건이 요청과 응답을 가를 수 없는 행으로 남았고, 151022 는 짝 없는 FC 23 / FC 15 예외 응답 15,734 행이 쓰기 요청 대신 남았다. 수와 원인은 [`samples/README.md`](samples/README.md#zeek-icsnpp-로그로-같은-캡처를-읽으면-2026-11-01)에 있다.

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
| **S7comm-plus 는 정책에서 별도 이름이다** — `S7COMM` 규칙이 덮지 않는다 | `PolicyReconcileIntegrationTest.S7COMM_허용은_S7COMM_PLUS_를_허용하지_않는다` · `ZeekEndToEndTest.S7COMM_선언은_S7comm_plus_를_덮지_않는다` |
| **pcap 에서 읽든 Zeek 로그에서 읽든 같은 요청은 같게 판정한다** | `IcsnppCrossCheckTest.snap7_은_두_길이_같은_요청을_같게_판정한다` · `modbus_example_은_대상_표기까지_같다` |
| **갭 이후 구간은 잔여 0 으로 끝날 때만 받는다** — 중간부터 시작한 구간은 통째로 버린다 | `RunReaderTest.이후_구간은_잔여가_0일_때만_받는다` |
| **못 본 바이트를 리포트가 말한다** — 캡처에 없던 것과 해독 못 한 것의 합 | `EndToEndTest.리포트는_못_본_바이트를_비율과_함께_낸다` · `CoexistenceTest.산업_대화의_못_본_바이트를_센다` |
| **프로토콜별 커버리지를 낸다** — 없는 프로토콜도 0 행으로 드러난다 | `CoexistenceTest.프로토콜별_커버리지가_합산과_맞는다` · `대화를_하나도_주장하지_못한_프로토콜도_행을_낸다` |
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
| **pcap 에서 S7comm-plus 해독** · **Userdata(ROSCTR 7) 해석** | S7comm-plus 는 대신 Zeek ICSNPP 로그(`--zeek-log`)로 읽는다. 4SICS 세 캡처에는 디코더를 검증할 S7comm-plus 프레임이 0 이다. Userdata 는 두 경로 모두 해석하지 않고, 로그 경로에서는 그 요청이 `UNDECIDABLE` 이 된다 |
| **갭 이후 구간의 재동기화** | 갭 이후 구간은 **엄격 적합**으로만 읽는다 — 오프셋 0 에서 시작해 잔여 0 으로 끝날 때만 받고, 경계를 찾아 스캔하지는 않는다. 중간부터 시작한 구간은 통째로 버리고 그 바이트를 리포트에 낸다 |
| **게이트웨이 뒤 유닛ID 단위 판정** | 정책이 IP 기준이라 시리얼 게이트웨이 경유 우회는 보이지 않는다. 유닛ID 를 정책에 넣으려면 계약 자체를 바꿔야 한다 |
| **재동기화** | 프레임 경계를 찾아 앞으로 스캔하지 않는다. 임의 바이너리를 Modbus 로 오인하면 미등록 쌍에서 HIGH 가 만들어진다 — 오탐이 오검출보다 비싸다 |
| **절대 성능 주장** | 로컬 측정으로는 증명되지 않는다 |

## 구조

```
pcap/       pcap 파일 → 패킷. 링크레이어·IPv4·TCP 스트림 재조립
decode/     Modbus/TCP · S7comm → Observation  ← 프로토콜 지식은 여기서 끝난다
zeek/       Zeek ICSNPP 로그 → Observation
contract/   CommunicationPolicy 읽기
reconcile/  관찰 ↔ 선언 대사 → Finding    ← 순수 로직. 입출력도 프로토콜 지식도 없다
cli/        진입점과 리포트
```

`pcap` · `decode` · `reconcile` · `zeek` 에는 런타임 서드파티 의존이 없다. YAML 을 읽는 `contract` 만 Jackson 을 쓴다.

`zeek/` 는 로그 형식 지식만 담는다 — 헤더, 어느 행이 요청인지, 어느 열이 송신자인지. 함수 코드 표는 `decode` 에 그대로 두고 재사용하므로, pcap 에서 읽은 요청과 Zeek 로그에서 읽은 같은 요청은 같은 표로 판정된다. `zeek/` 와 `cli/` 밖에서 바뀐 것은 `reconcile` 의 열거형 상수 하나(`S7COMM_PLUS`)와, `decode` 에 더한 `S7PlusAccess` 표와 공개 메서드 하나(`S7ObjectRef.ofFunction`)다.

```bash
mvn test
```

테스트는 313 건이다. 7 건은 4SICS 실캡처(`HUGINN_SAMPLES`), 3 건은 그 캡처의 Zeek 로그(`HUGINN_ZEEK_SAMPLES`), 2 건은 ICSNPP 트레이스(`HUGINN_ICSNPP_TRACES`)가 있을 때만 돈다.
없으면 건너뛰므로 기본 실행은 301 건이고, ICSNPP 트레이스를 내려받는 CI 는 303 건을 돌린다 — `samples/README.md` 참조.

설계와 구현 계획은 [`docs/superpowers/`](docs/superpowers/) 아래에 있다.

## 라이선스

Apache-2.0 — [LICENSE](LICENSE)
