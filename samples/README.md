# 공개 캡처로 반증 조건 시험하기

설계 §10 의 첫 반증 조건은 이것이다 — *"공개 ICS 캡처에서 `UNDECIDABLE` 비율이 압도적이면
Modbus 단독으로 유의미한 판정이 된다는 전제가 틀린 것"*. **내려받기만 하고 실행하지 않으면
이 조건은 한 번도 시험되지 않는다.**

## 상태

> **아직 시험되지 않았다.** 스크립트는 있고 파이프라인은 합성 캡처로 통과하지만,
> 실제 공개 캡처를 돌린 기록이 아래 표에 없다. 표가 비어 있는 동안 §10 은 미판정이다.

## 하는 법

```bash
bash scripts/fetch-samples.sh          # 또는  pwsh scripts/fetch-samples.ps1
mvn -DskipTests package
java -Dstdout.encoding=UTF-8 -jar cli/target/huginn.jar samples/<capture>.pcap samples/<capture>-policy.yaml
```

`editcap`(Wireshark)이 필요하다 — 배포되는 캡처가 pcapng 이면 `PcapReader` 가 거부하므로
스크립트가 pcap 으로 정규화한다. 캡처 자체는 커밋하지 않는다(라이선스가 제각각).

정책 파일은 캡처에서 관찰된 통신 중 **일부만** 선언해 만든다 — 전부 선언하면 위반이 0 건이라
대사가 실제로 도는지 알 수 없다.

## 결과

| 캡처 | 처리 패킷 | 대상 외 패킷 | 해독한 대화 | 대상 외 대화 | UNDECIDABLE 대화 | UNDECIDABLE 관찰 | 판정 |
|---|---|---|---|---|---|---|---|
| _(아직 없음)_ | | | | | | | |

`UNDECIDABLE` 비율이 높으면 원인을 적는다 — 프로토콜 선택이 틀렸는가, 요청/응답 판정이
R1·R2·R4(형태 모순·신호 불일치·둘 다 침묵)나 R5(단방향 캡처)로 빠졌는가, 캡처가 대화
중간부터 시작하는가. **판정 결과는 설계 문서 §10 에 반영한다.**
