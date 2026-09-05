# Huginn 1차 (Modbus/TCP) 구현 계획

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** pcap 파일에서 Modbus/TCP 요청을 해독해 선언된 `CommunicationPolicy`와 대조하고, 미등록 통신을 근거와 함께 보고하는 CLI를 만든다.

**Architecture:** 이음매(`Observation`)를 먼저 고정하고 아래로 내려간다. 순수 대사 로직 → pcap 읽기 → Modbus 해독 순. 요청/응답 방향은 포트 관례가 아니라 **PDU 구조**로 판정한다 — 포트는 거울상을 구별하지 못한다. `decode` 밖은 프레이밍·함수코드를 모르며, 그 경계는 2차에 S7comm을 붙일 때 시험받는다. pcap·프로토콜 파싱은 외부 의존 없이 직접 구현해 테스트가 환경을 타지 않게 한다.

**Tech Stack:** Java 17 · Maven 멀티모듈 · JUnit 5.10.3 · Jackson(`contract` 모듈 한정) · 그 외 런타임 의존 없음

**설계 문서:** `docs/superpowers/specs/2026-09-05-huginn-design.md`

**저장소 상태:** git 초기화 완료, `.gitignore`(`target/` 포함) 있음, 설계·계획 문서가 커밋되어 있다. 코드는 아직 0줄.

---

## 파일 구조

| 모듈 | artifactId | 책임 | 서드파티 | 모듈 간 |
|---|---|---|---|---|
| `contract/` | `huginn-contract` | `CommunicationPolicy` 로딩·검증 | Jackson(YAML) | `huginn-reconcile` |
| `reconcile/` | `huginn-reconcile` | `Observation` 이음매, 대사, `Finding` | **없음** | 없음 |
| `pcap/` | `huginn-pcap` | pcap 파일 → 패킷 → TCP 스트림 | **없음** | 없음 |
| `decode/` | `huginn-decode` | MBAP 프레이밍·함수코드·PDU 형태 → `Observation` | **없음** | `huginn-reconcile` · `huginn-pcap` |
| `cli/` | `huginn-cli` | 배선·리포트 | **없음** | 위 전부 · `huginn-pcap`·`huginn-decode` test-jar(테스트 한정, Task 14) |

**`서드파티` 열의 "없음"은 런타임 서드파티 라이브러리가 없다는 뜻이다.** 모듈 간 의존은 `모듈 간` 열대로 있다.

`reconcile`이 `Observation`과 `PolicyView`를 소유한다 — 이음매의 주인은 소비하는 쪽이어야 `contract → reconcile` 한 방향이 유지된다.

---

## Chunk 1: 이음매와 대사

바이너리를 만지기 전에 순수 로직부터 세운다. 이 청크가 끝나면 `Observation` 목록과 정책 파일만으로 대사가 돌아가고, **두 타입이 실제로 함께 도는 테스트까지 청크 안에서 닫힌다.**

### Task 1: Maven 골격

**Files:**
- Create: `pom.xml`
- Create: `reconcile/pom.xml`, `contract/pom.xml`, `pcap/pom.xml`, `decode/pom.xml`, `cli/pom.xml`

- [ ] **Step 1: 부모 POM 작성**

`pom.xml` — Bifrost 관례를 따른다(`dev.krillin.*`, `maven.compiler.release=17`, 버전은 부모에 집중).

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
  <modelVersion>4.0.0</modelVersion>

  <groupId>dev.krillin.huginn</groupId>
  <artifactId>huginn-parent</artifactId>
  <version>0.1.0-SNAPSHOT</version>
  <packaging>pom</packaging>
  <name>Huginn Parent</name>

  <modules>
    <module>reconcile</module>
    <module>contract</module>
    <module>pcap</module>
    <module>decode</module>
    <module>cli</module>
  </modules>

  <properties>
    <maven.compiler.release>17</maven.compiler.release>
    <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
    <jackson.version>2.17.2</jackson.version>
    <junit.version>5.10.3</junit.version>
    <maven-surefire-plugin.version>3.2.5</maven-surefire-plugin.version>
    <maven-shade-plugin.version>3.6.0</maven-shade-plugin.version>
    <maven-jar-plugin.version>3.4.1</maven-jar-plugin.version>
  </properties>

  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>com.fasterxml.jackson.dataformat</groupId>
        <artifactId>jackson-dataformat-yaml</artifactId>
        <version>${jackson.version}</version>
      </dependency>
      <dependency>
        <groupId>com.fasterxml.jackson.core</groupId>
        <artifactId>jackson-databind</artifactId>
        <version>${jackson.version}</version>
      </dependency>
      <dependency>
        <groupId>org.junit.jupiter</groupId>
        <artifactId>junit-jupiter</artifactId>
        <version>${junit.version}</version>
        <scope>test</scope>
      </dependency>
    </dependencies>
  </dependencyManagement>

  <dependencies>
    <dependency>
      <groupId>org.junit.jupiter</groupId>
      <artifactId>junit-jupiter</artifactId>
    </dependency>
  </dependencies>

  <build>
    <pluginManagement>
      <plugins>
        <plugin>
          <groupId>org.apache.maven.plugins</groupId>
          <artifactId>maven-surefire-plugin</artifactId>
          <version>${maven-surefire-plugin.version}</version>
        </plugin>
        <plugin>
          <groupId>org.apache.maven.plugins</groupId>
          <artifactId>maven-shade-plugin</artifactId>
          <version>${maven-shade-plugin.version}</version>
        </plugin>
        <plugin>
          <groupId>org.apache.maven.plugins</groupId>
          <artifactId>maven-jar-plugin</artifactId>
          <version>${maven-jar-plugin.version}</version>
        </plugin>
      </plugins>
    </pluginManagement>
  </build>
</project>
```

- [ ] **Step 2: 모듈 POM 5개 작성**

**artifactId 규칙: `huginn-<디렉터리명>`.** 모두 부모를 상속하고 아래 의존만 더한다(JUnit은 부모에서 상속되므로 어디에도 다시 적지 않는다).

| 모듈 | 추가할 `<dependencies>` |
|---|---|
| `reconcile` | 없음 |
| `pcap` | 없음 |
| `contract` | `huginn-reconcile` · `jackson-databind` · `jackson-dataformat-yaml` |
| `decode` | `huginn-reconcile` · `huginn-pcap` |
| `cli` | `huginn-reconcile` · `huginn-contract` · `huginn-pcap` · `huginn-decode` |

`reconcile/pom.xml` 전문(나머지는 `artifactId`와 위 표의 의존만 바꿔 동일한 골격을 쓴다):

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
  <modelVersion>4.0.0</modelVersion>
  <parent>
    <groupId>dev.krillin.huginn</groupId>
    <artifactId>huginn-parent</artifactId>
    <version>0.1.0-SNAPSHOT</version>
  </parent>
  <artifactId>huginn-reconcile</artifactId>
  <name>Huginn Reconcile</name>
</project>
```

모듈 간 의존은 `${project.groupId}` / `${project.version}`을 쓴다.

- [ ] **Step 3: 리액터 해석 확인**

Run: `mvn -DskipTests package`
Expected: `BUILD SUCCESS`. 5개 모듈이 리액터에 잡히고 모듈 간 참조가 해석되어야 한다. (`-q`는 성공 메시지를 감추므로 여기서는 쓰지 않는다.)

- [ ] **Step 4: 커밋**

```bash
git add pom.xml reconcile/pom.xml contract/pom.xml pcap/pom.xml decode/pom.xml cli/pom.xml
git commit -m "build: Maven 멀티모듈 골격 5개"
```

---

### Task 2: 이음매 타입

**Files:**
- Create: `reconcile/src/main/java/dev/krillin/huginn/reconcile/Endpoint.java`
- Create: `reconcile/src/main/java/dev/krillin/huginn/reconcile/Protocol.java`
- Create: `reconcile/src/main/java/dev/krillin/huginn/reconcile/Access.java`
- Create: `reconcile/src/main/java/dev/krillin/huginn/reconcile/Observation.java`
- Test: `reconcile/src/test/java/dev/krillin/huginn/reconcile/EndpointTest.java`

- [ ] **Step 1: 실패하는 테스트 작성**

값 타입 자체는 테스트하지 않는다. 유일하게 로직이 있는 것은 `Endpoint` 표기다.

```java
package dev.krillin.huginn.reconcile;

import static org.junit.jupiter.api.Assertions.assertEquals;
import org.junit.jupiter.api.Test;

class EndpointTest {
    @Test
    void 주소와_포트를_사람이_읽는_형태로_표기한다() {
        assertEquals("10.0.1.20:502", new Endpoint("10.0.1.20", 502).toString());
    }
}
```

- [ ] **Step 2: 실패 확인**

Run: `mvn -pl reconcile test`
Expected: 컴파일 실패 — `Endpoint` 심볼을 찾을 수 없음

- [ ] **Step 3: 최소 구현**

```java
package dev.krillin.huginn.reconcile;

/** 통신 한쪽 끝. 주소는 문자열로 둔다 — 판정에 산술이 필요 없고, 표기가 그대로 근거가 된다. */
public record Endpoint(String address, int port) {
    @Override public String toString() { return address + ":" + port; }
}
```

```java
package dev.krillin.huginn.reconcile;

/**
 * 해독한 산업 프로토콜.
 *
 * 이 열거형이 reconcile 에 있는 것은 정책 계약이 프로토콜을 이름으로 선언하기 때문이다.
 * decode 경계가 막는 것은 프로토콜 "이름" 이 아니라 프레이밍·함수코드 지식이다.
 */
public enum Protocol { MODBUS_TCP }
```

```java
package dev.krillin.huginn.reconcile;

/**
 * 접근 유형.
 *
 * UNDECIDABLE 이 값 하나로 존재하는 것이 요점이다 — 해독 못 한 것을 READ 로 치면 우회를 놓친다.
 */
public enum Access { READ, WRITE, CONTROL, UNDECIDABLE }
```

```java
package dev.krillin.huginn.reconcile;

import java.time.Instant;

/**
 * 관찰 한 건. 프로토콜 지식은 이 타입을 만드는 쪽(decode)에서 끝난다.
 *
 * 설계 §5-⑤ 에 따라 **요청만** Observation 이 된다. 응답은 출발지·목적지가 뒤집혀 있어
 * 관찰하면 정상 통신이 전부 위반이 된다.
 *
 * @param at        이 관찰이 속한 방향 스트림의 가장 이른 세그먼트 시각. 프레임 단위 시각은 오프셋→시각 맵이 있어야 하므로 1차 범위 밖이고, 한 스트림의 관찰 여럿이 같은 시각을 갖는다
 * @param objectRef 건드린 대상의 프로토콜별 정규화 표기(예: "holding:40001"). 근거 표시용이며 판정에는 쓰지 않는다.
 */
public record Observation(
    Instant at,
    Endpoint source,
    Endpoint target,
    Protocol protocol,
    Access access,
    String objectRef
) {}
```

- [ ] **Step 4: 통과 확인**

Run: `mvn -pl reconcile test`
Expected: `Tests run: 1, Failures: 0, Errors: 0`

- [ ] **Step 5: 커밋**

```bash
git add reconcile/src
git commit -m "feat: Observation 이음매 타입"
```

---

### Task 3: `CommunicationPolicy` 로딩

**Files:**
- Create: `contract/src/main/java/dev/krillin/huginn/contract/CommunicationPolicy.java`
- Create: `contract/src/main/java/dev/krillin/huginn/contract/PolicyLoader.java`
- Create: `contract/src/main/java/dev/krillin/huginn/contract/PolicyException.java`
- Create: `contract/src/main/java/dev/krillin/huginn/contract/PolicyDocument.java`
- Test: `contract/src/test/java/dev/krillin/huginn/contract/PolicyLoaderTest.java`

- [ ] **Step 1: 실패하는 테스트 작성**

계약 오류는 **즉시 실패**다(설계 §7). 잘못된 계약을 통과시키면 deny-by-default 때문에 전부 위반으로 쏟아진다.

```java
package dev.krillin.huginn.contract;

import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.Test;
import dev.krillin.huginn.reconcile.Access;
import dev.krillin.huginn.reconcile.Protocol;

class PolicyLoaderTest {

    private static final String VALID = """
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
        """;

    @Test
    void 유효한_정책을_읽는다() {
        CommunicationPolicy p = PolicyLoader.parse(VALID);
        assertTrue(p.allows("10.0.1.20", "10.0.2.11", Protocol.MODBUS_TCP, Access.WRITE));
        assertTrue(p.allows("10.0.1.20", "10.0.2.11", Protocol.MODBUS_TCP, Access.READ));
    }

    @Test
    void 선언되지_않은_접근은_허용하지_않는다() {
        CommunicationPolicy p = PolicyLoader.parse(VALID);
        assertFalse(p.allows("10.0.1.20", "10.0.2.11", Protocol.MODBUS_TCP, Access.CONTROL));
    }

    @Test
    void 선언되지_않은_주소는_허용하지_않는다() {
        CommunicationPolicy p = PolicyLoader.parse(VALID);
        assertFalse(p.allows("10.0.9.99", "10.0.2.11", Protocol.MODBUS_TCP, Access.READ));
    }

    @Test
    void UNDECIDABLE은_결코_허용되지_않는다() {
        // 해독하지 못한 것을 허용으로 치면 우회를 놓친다.
        CommunicationPolicy p = PolicyLoader.parse(VALID);
        assertFalse(p.allows("10.0.1.20", "10.0.2.11", Protocol.MODBUS_TCP, Access.UNDECIDABLE));
    }

    @Test
    void 알_수_없는_peer를_참조하면_즉시_실패한다() {
        String bad = VALID.replace("to: plc-mixer", "to: ghost");
        PolicyException e = assertThrows(PolicyException.class, () -> PolicyLoader.parse(bad));
        assertTrue(e.getMessage().contains("ghost"), "어느 peer 가 문제인지 메시지에 있어야 한다");
    }

    @Test
    void peer_id가_중복되면_즉시_실패한다() {
        assertThrows(PolicyException.class, () -> PolicyLoader.parse(VALID.replace("id: plc-mixer", "id: hmi-01")));
    }

    @Test
    void 서로_다른_peer가_같은_주소를_쓰면_즉시_실패한다() {
        // 주소→id 역인덱스가 조용히 덮이면 판정이 어느 선언을 따랐는지 알 수 없게 된다.
        assertThrows(PolicyException.class, () -> PolicyLoader.parse(VALID.replace("10.0.2.11", "10.0.1.20")));
    }

    @Test
    void 지원하지_않는_version이면_즉시_실패한다() {
        assertThrows(PolicyException.class, () -> PolicyLoader.parse(VALID.replace("version: 1", "version: 2")));
    }

    @Test
    void 알_수_없는_필드가_있으면_즉시_실패한다() {
        assertThrows(PolicyException.class, () -> PolicyLoader.parse(VALID + "unexpected: true\n"));
    }

    @Test
    void 깨진_YAML이면_즉시_실패한다() {
        assertThrows(PolicyException.class, () -> PolicyLoader.parse("version: 1\n  peers: [oops\n"));
    }

    @Test
    void 규칙에_protocol이_없으면_즉시_실패한다() {
        // Jackson 은 키가 없으면 null 을 준다. 검사하지 않으면 예외가 아니라
        // Key(from, to, null) 이 만들어져 그 규칙이 말없이 무효가 된다 —
        // 선언한 통신이 전부 위반으로 쏟아진다. 조용한 이상이 시끄러운 실패보다 나쁘다.
        PolicyException e = assertThrows(PolicyException.class,
            () -> PolicyLoader.parse(VALID.replace("    protocol: MODBUS_TCP
", "")));
        assertTrue(e.getMessage().contains("hmi-01"), "어느 규칙이 문제인지 메시지에 있어야 한다");
    }

    @Test
    void 규칙에_access가_없으면_NPE가_아니라_계약_오류다() {
        // addAll(null) 이 던지는 NPE 는 Task 14 의 종료 코드 매핑을 빠져나간다.
        assertThrows(PolicyException.class,
            () -> PolicyLoader.parse(VALID.replace("    access: [READ, WRITE]
", "")));
    }

    @Test
    void 같은_쌍의_규칙이_둘이면_access를_합친다() {
        // Map.put 으로 덮으면 앞의 READ 가 말없이 사라져 정상 통신이 위반으로 보고된다.
        CommunicationPolicy p = PolicyLoader.parse(VALID + """
              - from: hmi-01
                to: plc-mixer
                protocol: MODBUS_TCP
                access: [WRITE]
            """);
        assertTrue(p.allows("10.0.1.20", "10.0.2.11", Protocol.MODBUS_TCP, Access.READ));
        assertTrue(p.allows("10.0.1.20", "10.0.2.11", Protocol.MODBUS_TCP, Access.WRITE));
    }
}
```

> 마지막 테스트는 `VALID`의 `allowed` 목록에 항목을 하나 덧붙인다. `VALID`가 `allowed` 항목으로 끝나야 하고 이어붙이는 텍스트 블록의 들여쓰기가 그 항목과 맞아야 한다.

- [ ] **Step 2: 실패 확인**

Run: `mvn -pl contract -am test`
Expected: 컴파일 실패 — `CommunicationPolicy`·`PolicyLoader`·`PolicyException` 심볼 없음(`Access`·`Protocol`은 이미 있다)

- [ ] **Step 3: 구현**

`public class PolicyException extends RuntimeException`. 생성자는 `public PolicyException(String)`과 Jackson 예외 포장용 `public PolicyException(String, Throwable)` 둘. **`public`이어야 한다** — 청크 3의 `Huginn.run`(`cli` 패키지)이 이것을 잡아 종료 코드 2로 매핑한다. 청크 1 안에서는 `PolicyLoaderTest`가 같은 패키지라 끝까지 드러나지 않는다.

`PolicyDocument`는 Jackson 역직렬화 전용 DTO다 — 검증 전의 날 것이라 도메인 타입과 분리한다.

```java
package dev.krillin.huginn.contract;

import java.util.List;
import dev.krillin.huginn.reconcile.Access;
import dev.krillin.huginn.reconcile.Protocol;

/** YAML 역직렬화 전용. 검증은 PolicyLoader 가 한다. */
record PolicyDocument(int version, List<Peer> peers, List<Rule> allowed) {
    record Peer(String id, String address) {}
    record Rule(String from, String to, Protocol protocol, List<Access> access) {}
}
```

`PolicyLoader.parse`는 **`public static CommunicationPolicy parse(String yaml)`**다 — 클래스만 public 이고 메서드가 패키지-프라이빗이면 Task 14 `Pipeline`과 Task 16 `ExamplePolicyTest`에서 접근 불가로 깨진다:

1. `new ObjectMapper(new YAMLFactory())` — `FAIL_ON_UNKNOWN_PROPERTIES`는 기본이 켜짐이므로 **끄지 않는다.**
2. **Jackson이 던지는 모든 예외(`JacksonException`)를 `PolicyException`으로 감싼다.** 감싸지 않으면 `알_수_없는_필드`·`깨진_YAML` 테스트가 `UnrecognizedPropertyException`/`JsonParseException`을 받아 실패한다.
3. 검증 — `version != 1`, `peers`/`allowed` null, peer id 중복, peer address 중복, `allowed`의 `from`/`to`가 미선언 id, **`allowed` 항목의 `protocol`·`access` null**. **실패 메시지에 문제된 id나 주소를 포함한다.**

   마지막 둘이 필요한 이유. YAML에서 키를 빠뜨리면 Jackson은 예외가 아니라 **null**을 준다.
   - `access:` 누락 → 합집합 merge에서 `addAll(null)`이 **NPE**다. Task 14는 `PolicyException`·`PcapException`만 잡아 종료 코드 2로 매핑하므로 날 NPE는 그 그물을 빠져나가 스택 트레이스로 죽는다 — 설계 §7의 "계약 오류는 즉시, **정의된 방식으로** 실패"가 깨진다.
   - `protocol:` 누락 → 예외가 아니라 `Key(from, to, null)`이 만들어진다. 어떤 관찰과도 매칭되지 않으므로 **그 규칙이 말없이 무효가 되고 선언한 통신이 전부 위반으로 보고된다.** 조용한 이상이라 앞의 것보다 위험하다.
4. `(fromAddress, toAddress, protocol) → Set<Access>` 조회표를 만들어 `CommunicationPolicy`를 반환한다. **같은 키가 두 번 나오면 `Map.put`으로 덮지 말고 access 집합을 합집합으로 merge한다** — 덮으면 앞의 `access: [READ]`가 말없이 사라져 정상 통신이 위반으로 보고된다. 다른 중복(peer id·주소)은 전부 즉시 실패시키면서 이것만 조용히 덮이는 것은 이 계약의 기조에 어긋난다. 주소→id 역인덱스는 **판정에 쓰이지 않는다** — 조회표가 이미 주소로 키를 잡는다. 역인덱스의 용도는 3의 주소 중복 검증과 사람이 읽는 오류 메시지뿐이므로, 그 둘에 필요한 만큼만 만든다.

`CommunicationPolicy`와 `PolicyLoader`는 **`public` 클래스**다(청크 3의 `cli`가 둘 다 부른다). `CommunicationPolicy`는 **`public boolean allows(String, String, Protocol, Access)` 하나만 노출**한다. `Access.UNDECIDABLE`이 들어오면 **조회 전에 false**를 반환한다.

**여기서 `PolicyView`를 참조하지 않는다.** 그 인터페이스는 Task 4에서 만들어지고 Task 5에서 붙인다 — 지금 참조하면 심볼이 없어 컴파일이 깨지고, 미리 만들면 Task 5의 RED가 사라진다. `allows`를 **public**으로 두는 것이 나중에 인터페이스를 붙일 때 시그니처가 그대로 맞는 조건이다.

- [ ] **Step 4: 통과 확인**

Run: `mvn -pl contract -am test`
Expected: `contract` 모듈 `Tests run: 13, Failures: 0`. (`-am` 때문에 `reconcile`의 1건도 함께 돌아 리액터 총합은 14이다.)

- [ ] **Step 5: 커밋**

```bash
git add contract/src
git commit -m "feat: CommunicationPolicy 로딩 — 계약 오류는 즉시 실패"
```

---

### Task 4: 대사기

**Files:**
- Create: `reconcile/src/main/java/dev/krillin/huginn/reconcile/PolicyView.java`
- Create: `reconcile/src/main/java/dev/krillin/huginn/reconcile/Severity.java`
- Create: `reconcile/src/main/java/dev/krillin/huginn/reconcile/Finding.java`
- Create: `reconcile/src/main/java/dev/krillin/huginn/reconcile/ReconcileResult.java`
- Create: `reconcile/src/main/java/dev/krillin/huginn/reconcile/Reconciler.java`
- Test: `reconcile/src/test/java/dev/krillin/huginn/reconcile/ReconcilerTest.java`

- [ ] **Step 1: 실패하는 테스트 작성**

```java
package dev.krillin.huginn.reconcile;

import static org.junit.jupiter.api.Assertions.*;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;

class ReconcilerTest {

    private final Endpoint hmi = new Endpoint("10.0.1.20", 40000);
    private final Endpoint plc = new Endpoint("10.0.2.11", 502);
    private final Endpoint rogue = new Endpoint("10.0.9.99", 40000);

    /** hmi → plc 의 Modbus READ 만 허용한다. */
    private final PolicyView policy = (src, dst, proto, access) ->
        src.equals("10.0.1.20") && dst.equals("10.0.2.11")
            && proto == Protocol.MODBUS_TCP && access == Access.READ;

    private Observation obs(Endpoint s, Endpoint t, Access a) {
        return new Observation(Instant.EPOCH, s, t, Protocol.MODBUS_TCP, a, "holding:40001");
    }

    @Test
    void 선언된_통신은_Finding을_만들지_않는다() {
        ReconcileResult r = new Reconciler(policy).reconcile(List.of(obs(hmi, plc, Access.READ)));
        assertTrue(r.findings().isEmpty());
        assertEquals(1, r.observedCount());
        assertEquals(0, r.undecidableCount());
    }

    @Test
    void 미등록_출발지는_잡힌다() {
        ReconcileResult r = new Reconciler(policy).reconcile(List.of(obs(rogue, plc, Access.READ)));
        assertEquals(1, r.findings().size());
        assertEquals(Finding.Kind.UNDECLARED, r.findings().get(0).kind());
    }

    @Test
    void 허용되지_않은_쓰기는_잡힌다() {
        ReconcileResult r = new Reconciler(policy).reconcile(List.of(obs(hmi, plc, Access.WRITE)));
        assertEquals(1, r.findings().size());
        assertEquals(Severity.HIGH, r.findings().get(0).severity());
    }

    @Test
    void 쓰기가_읽기보다_심각도가_높다() {
        Reconciler r = new Reconciler(policy);
        Severity write = r.reconcile(List.of(obs(rogue, plc, Access.WRITE))).findings().get(0).severity();
        Severity read = r.reconcile(List.of(obs(rogue, plc, Access.READ))).findings().get(0).severity();
        assertTrue(write.compareTo(read) > 0);
    }

    @Test
    void 제어는_쓰기와_같은_심각도다() {
        Reconciler r = new Reconciler(policy);
        assertEquals(Severity.HIGH,
            r.reconcile(List.of(obs(rogue, plc, Access.CONTROL))).findings().get(0).severity());
    }

    @Test
    void 해독하지_못한_관찰은_Finding이_아니라_따로_센다() {
        ReconcileResult r = new Reconciler(policy).reconcile(List.of(obs(hmi, plc, Access.UNDECIDABLE)));
        assertTrue(r.findings().isEmpty(), "판정할 수 없는 것을 위반으로 단정하지 않는다");
        assertEquals(1, r.undecidableCount(), "그렇다고 조용히 넘기지도 않는다");
        assertEquals(1, r.observedCount(), "observedCount 는 UNDECIDABLE 을 포함한다");
    }

    @Test
    void Finding은_근거_관찰을_들고_있다() {
        Observation o = obs(rogue, plc, Access.WRITE);
        Finding f = new Reconciler(policy).reconcile(List.of(o)).findings().get(0);
        assertEquals(o, f.evidence());
        assertFalse(f.detail().isBlank(), "무엇이 어긋났는지 사람이 읽을 수 있어야 한다");
    }

    @Test
    void 같은_입력에_같은_결과가_같은_순서로_나온다() {
        List<Observation> input = List.of(
            obs(rogue, plc, Access.WRITE), obs(hmi, plc, Access.READ), obs(rogue, plc, Access.READ));
        Reconciler r = new Reconciler(policy);
        assertEquals(r.reconcile(input).findings(), r.reconcile(input).findings());
    }
}
```

- [ ] **Step 2: 실패 확인**

Run: `mvn -pl reconcile test`
Expected: 컴파일 실패 — `PolicyView`·`Severity`·`Finding`·`ReconcileResult`·`Reconciler` 심볼 없음. 다른 이유로 깨지면 멈추고 원인을 본다

- [ ] **Step 3: 구현**

```java
package dev.krillin.huginn.reconcile;

/** 대사기가 정책에 대해 아는 전부. contract 모듈이 이것을 구현한다 — 의존 방향은 contract → reconcile 이다. */
@FunctionalInterface
public interface PolicyView {
    boolean allows(String sourceAddress, String targetAddress, Protocol protocol, Access access);
}
```

```java
package dev.krillin.huginn.reconcile;

/** 선언 순서가 곧 심각도 순서다(compareTo 로 비교 가능). */
public enum Severity { MEDIUM, HIGH }
```

`Finding`:

```java
package dev.krillin.huginn.reconcile;

public record Finding(Severity severity, Kind kind, Observation evidence, String detail) {
    /**
     * 1차는 한 종류다. UNDECLARED_PEER/PROTOCOL/ACCESS 로 나눌 수 있지만, 근거 Observation 이
     * 이미 무엇이 어긋났는지를 담고 있어 세분화의 실익이 아직 없다(설계 §5).
     */
    public enum Kind { UNDECLARED }
}
```

`ReconcileResult`: `public record ReconcileResult(List<Finding> findings, int observedCount, int undecidableCount)`. **`observedCount`는 입력 `Observation` 총수이며 `UNDECIDABLE`을 포함한다.**

`Reconciler`는 `public final class`이고 생성자는 `public Reconciler(PolicyView policy)`다. **`ReconcileResult`와 함께 반드시 `public`이어야 한다** — Task 5의 통합 테스트가 `dev.krillin.huginn.contract` 패키지에 있어 패키지-프라이빗이면 컴파일되지 않는다. Task 5 Step 2가 이미 컴파일 실패를 기대하므로 그 실패에 가려져 Step 4에서야 드러난다.

`Reconciler.reconcile`은 **`public ReconcileResult reconcile(List<Observation>)`**다(멤버까지 public 이어야 Task 5·청크 3이 부른다). 입력 순서를 유지하며 한 번 훑는다.
- `access == UNDECIDABLE` → 정책을 조회하지 않고 `undecidableCount`만 올린다
- `policy.allows(...)`가 true → 아무것도 하지 않는다
- 그 외 → `Finding` 하나. `Severity`는 `WRITE`·`CONTROL` → `HIGH`, `READ` → `MEDIUM`
- `detail`은 사람이 읽는 한 문장으로 만든다. 규약: `"선언되지 않은 통신: <source> → <target> <protocol> <access>"`

- [ ] **Step 4: 통과 확인**

Run: `mvn -pl reconcile test`
Expected: `Tests run: 9, Failures: 0` (`EndpointTest` 1 + `ReconcilerTest` 8)

- [ ] **Step 5: 커밋**

```bash
git add reconcile/src
git commit -m "feat: 대사기 — deny-by-default, UNDECIDABLE은 위반이 아니라 별도 계수"
```

---

### Task 5: 이음매 닫기 — 정책과 대사기를 함께 돌린다

**Files:**
- Modify: `contract/src/main/java/dev/krillin/huginn/contract/CommunicationPolicy.java` — `implements PolicyView`
- Test: `contract/src/test/java/dev/krillin/huginn/contract/PolicyReconcileIntegrationTest.java`

이 청크의 중심 주장은 "`CommunicationPolicy`가 `PolicyView`를 구현한다"인데, 컴파일만 통과하면 두 타입이 실제로 함께 도는 경로는 청크 3까지 한 번도 실행되지 않는다. **여기서 닫는다.**

- [ ] **Step 1: 실패하는 테스트 작성**

```java
package dev.krillin.huginn.contract;

import static org.junit.jupiter.api.Assertions.*;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;
import dev.krillin.huginn.reconcile.*;

class PolicyReconcileIntegrationTest {

    private static final String POLICY = """
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
            access: [READ]
        """;

    private Observation obs(String src, String dst, Access a) {
        return new Observation(Instant.EPOCH, new Endpoint(src, 40000), new Endpoint(dst, 502),
            Protocol.MODBUS_TCP, a, "holding:40001");
    }

    @Test
    void 파일로_선언한_정책이_대사기에_그대로_먹힌다() {
        Reconciler r = new Reconciler(PolicyLoader.parse(POLICY));

        ReconcileResult result = r.reconcile(List.of(
            obs("10.0.1.20", "10.0.2.11", Access.READ),    // 허용
            obs("10.0.1.20", "10.0.2.11", Access.WRITE),   // 쓰기는 선언 안 됨
            obs("10.0.9.99", "10.0.2.11", Access.READ)));  // 미등록 출발지

        assertEquals(2, result.findings().size());
        assertEquals(3, result.observedCount());
    }
}
```

- [ ] **Step 2: 실패 확인**

Run: `mvn -pl contract -am test`
Expected: 컴파일 실패 — `CommunicationPolicy`가 아직 `PolicyView`가 아님

- [ ] **Step 3: 구현**

`CommunicationPolicy`에 `implements PolicyView`를 붙인다. 시그니처는 이미 맞으므로 다른 변경은 없다.

- [ ] **Step 4: 통과 확인**

Run: `mvn test`
Expected: 전체 `BUILD SUCCESS`, `contract` 14건 + `reconcile` 9건. **`pcap`·`decode`·`cli` 세 모듈은 아직 테스트가 0건이며 그게 정상이다** — 소스가 없는 모듈의 빈 surefire 실행은 실패가 아니다.

- [ ] **Step 5: 커밋**

```bash
git add contract/src
git commit -m "test: 정책 파일과 대사기가 함께 도는 경로를 청크 안에서 닫는다"
```

---

## Chunk 2: pcap 읽기

바이너리 계층. **합성 pcap 빌더를 먼저 만든다** — 그것 없이는 아무것도 결정적으로 테스트할 수 없다.

이 청크가 하류의 정확성을 좌우하는 결정을 **전부 여기서 내린다.** 미루면 청크 3의 구현자가 임의로 정하게 된다.

| 결정 | 값 | 이유 |
|---|---|---|
| TCP 페이로드 길이 | `IPv4 totalLength − IHL*4 − dataOffset*4` | 캡처 잔여 바이트로 자르면 **이더넷 최소 프레임 패딩(60바이트)**이 스트림에 섞인다. 짧은 Modbus 응답은 거의 항상 패딩 대상이라 일상이다 |
| 길이 0 세그먼트 | **조립에서 제외** | SYN·FIN은 seq를 1 소비한다. 제외하지 않으면 핸드셰이크가 잡힌 **모든 스트림이 1바이트 갭 → 전량 UNDECIDABLE**이 된다 |
| base seq | **바이트를 기여하는(길이 > 0) 세그먼트 중 최소 seq** | 캡처가 대화 중간부터 시작하면 첫 seq는 임의값이다. **길이 0 세그먼트를 후보에 넣으면 SYN(seq n)이 base가 되고 첫 데이터(seq n+1)가 오프셋 1에 놓여 1바이트 갭이 생긴다** — 아래 "길이 0 세그먼트 제외"가 막으려던 바로 그 실패가 base 계산으로 되살아난다 |
| 겹치는 재전송 | **먼저 온 바이트가 이긴다**(first-wins). seq가 같으면 **입력 순서가 이긴다**(정렬은 stable) | 나중 세그먼트로 앞 내용을 덮어쓸 수 있으면 재전송 위장으로 판정을 속일 수 있다. seq가 같고 내용이 다른 쌍은 정렬이 불안정하면 어느 쪽이 이길지 비결정적이 되어 방어가 반만 닫힌다 |
| seq 랩어라운드 | **다루지 않는다** | 32비트를 `& 0xFFFFFFFFL`로 읽어 음수화만 막는다. 랩된 스트림은 갭으로 보고 UNDECIDABLE이 된다 |
| 스트림 열거 순서 | `LinkedHashMap` — 최초 등장 순서 | `HashMap`이면 리포트가 비결정적이 된다 |
| SYN 관찰 | `TcpSegment`가 **`syn`·`ack` 두 비트를 싣는다.** 조립기는 `syn && !ack`인 세그먼트를 본 방향에 **`sawSynOnly`**를 세운다. 바이트는 여전히 버린다 | 길이 0 세그먼트를 통째로 버리면 **연결을 연 쪽을 확정할 유일한 신호**까지 사라진다. 그리고 **`syn`만 보면 안 된다** — SYN+ACK도 SYN 비트가 서 있어 서버 방향에도 플래그가 서고, 그러면 핸드셰이크가 잡힌 모든 대화에서 양쪽이 같아져 근거가 무력해지거나 서버를 클라이언트로 읽는다. `!ack`가 그 구분을 한다 |
| 플래그를 어디까지 아는가 | `pcap` 모듈은 `syn`·`ack`라는 **사실**만 싣는다. "클라이언트"라는 **해석**은 청크 3이 한다 | 이름을 `sawClientSyn`으로 두면 전송 계층이 응용 계층의 역할을 알게 된다 |
| 유도 길이 > 실제 바이트 | **있는 만큼만 잘라내고 `truncated` 표시** | snaplen 절단은 흔한 경우다. 유도 길이만큼 자르려 들면 `IndexOutOfBoundsException`이 난다 |
| 체크섬 | **검증하지 않는다** | 빌더는 0으로 채운다. 손상 탐지는 이 도구의 목적이 아니다 |

### Task 6: 합성 pcap 빌더와 `PcapReader`

**Files:**
- Create: `pcap/src/main/java/dev/krillin/huginn/pcap/PcapReader.java`
- Create: `pcap/src/main/java/dev/krillin/huginn/pcap/CapturedPacket.java`
- Create: `pcap/src/main/java/dev/krillin/huginn/pcap/PcapException.java`
- Create: `pcap/src/test/java/dev/krillin/huginn/pcap/PcapBuilder.java` *(테스트 소스)*
- Test: `pcap/src/test/java/dev/krillin/huginn/pcap/PcapReaderTest.java`

- [ ] **Step 1: 빌더 작성**

libpcap 파일 포맷 — 글로벌 헤더 24바이트(magic, 버전 2.4, 타임존 0, sigfigs 0, snaplen, 링크타입), 이어서 패킷마다 16바이트 헤더(`ts_sec`, `ts_usec`, `incl_len`, `orig_len`) + 데이터.

```java
package dev.krillin.huginn.pcap;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * 테스트용 pcap 조립기. 외부 캡처 파일 없이 결정적으로 검증하기 위한 것이다.
 * <p>Task 14 의 cli E2E 테스트가 test-jar 를 통해 이것을 그대로 쓴다 — 그래서 클래스도
 * 정적 팩터리도 인스턴스 메서드도 전부 public 이다(private 생성자만 예외).
 * 클래스만 public 으로 두면 다른 패키지에서 ethernet() 부터 막힌다. 복제하면 두 벌이 갈라진다.
 * withSnaplen 은 PcapReader 가 snaplen 을 읽지도 쓰지도 않아 소비자가 없으므로 두지 않는다.
 */
public final class PcapBuilder {

    public static final int MAGIC_MICROS = 0xA1B2C3D4;
    public static final int MAGIC_NANOS  = 0xA1B23C4D;
    public static final int MAGIC_BIG_ENDIAN = 0xD4C3B2A1;
    public static final int MAGIC_PCAPNG = 0x0A0D0D0A;

    private final ByteArrayOutputStream out = new ByteArrayOutputStream();

    public static PcapBuilder ethernet() { return new PcapBuilder(1, MAGIC_MICROS, 65535); }
    public static PcapBuilder withMagic(int magic) { return new PcapBuilder(1, magic, 65535); }
    public static PcapBuilder withLinkType(int linkType) { return new PcapBuilder(linkType, MAGIC_MICROS, 65535); }

    private PcapBuilder(int linkType, int magic, int snaplen) {
        ByteBuffer h = ByteBuffer.allocate(24).order(ByteOrder.LITTLE_ENDIAN);
        h.putInt(magic).putShort((short) 2).putShort((short) 4)
         .putInt(0).putInt(0).putInt(snaplen).putInt(linkType);
        out.writeBytes(h.array());
    }

    /** 온전한 패킷 — incl_len == orig_len */
    public PcapBuilder packet(int seconds, int micros, byte[] payload) {
        return packet(seconds, micros, payload, payload.length);
    }

    /** 절단된 패킷 — incl_len(실제 저장) < orig_len(원본) */
    public PcapBuilder packet(int seconds, int micros, byte[] stored, int originalLength) {
        ByteBuffer h = ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN);
        h.putInt(seconds).putInt(micros).putInt(stored.length).putInt(originalLength);
        out.writeBytes(h.array());
        out.writeBytes(stored);
        return this;
    }

    /** 손상·악의적 파일 — 선언 길이가 실제 잔여보다 크다 */
    public PcapBuilder packetWithDeclaredLength(int seconds, int micros, byte[] stored, int declaredInclLen) {
        ByteBuffer h = ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN);
        h.putInt(seconds).putInt(micros).putInt(declaredInclLen).putInt(declaredInclLen);
        out.writeBytes(h.array());
        out.writeBytes(stored);
        return this;
    }

    public byte[] build() { return out.toByteArray(); }
}
```

- [ ] **Step 2: 실패하는 테스트 작성**

```java
@Test
void 빈_캡처는_패킷이_없다() {
    assertTrue(PcapReader.read(PcapBuilder.ethernet().build()).isEmpty());
}

@Test
void 패킷의_시각과_바이트를_보존한다() {
    byte[] pcap = PcapBuilder.ethernet().packet(1_700_000_000, 500_000, new byte[]{1, 2, 3}).build();
    List<CapturedPacket> packets = PcapReader.read(pcap);
    assertEquals(1, packets.size());
    assertEquals(Instant.ofEpochSecond(1_700_000_000L, 500_000_000L), packets.get(0).at());
    assertArrayEquals(new byte[]{1, 2, 3}, packets.get(0).data());
    assertFalse(packets.get(0).truncated());
}

@Test
void 절단된_패킷을_절단으로_표시한다() {
    // tcpdump -s 96 같은 설정에서는 모든 패킷이 잘려 온다.
    // 잘린 것을 온전한 것처럼 하류로 흘리면 프레임 경계가 어긋난다.
    byte[] pcap = PcapBuilder.ethernet().packet(1, 0, new byte[]{1, 2, 3}, 1500).build();
    CapturedPacket p = PcapReader.read(pcap).get(0);
    assertTrue(p.truncated());
    assertEquals(1500, p.originalLength());
}

@Test
void 매직넘버가_틀리면_즉시_실패한다() {
    assertThrows(PcapException.class, () -> PcapReader.read(PcapBuilder.withMagic(0xDEADBEEF).build()));
}

@Test
void 빅엔디언_pcap은_원인을_밝히며_거부한다() {
    PcapException e = assertThrows(PcapException.class,
        () -> PcapReader.read(PcapBuilder.withMagic(PcapBuilder.MAGIC_BIG_ENDIAN).build()));
    assertTrue(e.getMessage().contains("빅엔디언"));
}

@Test
void 나노초_해상도_pcap은_원인을_밝히며_거부한다() {
    PcapException e = assertThrows(PcapException.class,
        () -> PcapReader.read(PcapBuilder.withMagic(PcapBuilder.MAGIC_NANOS).build()));
    assertTrue(e.getMessage().contains("나노초"));
}

@Test
void pcapng는_원인을_밝히며_거부한다() {
    // Wireshark 기본 저장 형식이라 사용자가 가장 흔히 만난다.
    // "매직넘버가 틀림" 으로만 거부하면 원인을 못 찾는다.
    PcapException e = assertThrows(PcapException.class,
        () -> PcapReader.read(PcapBuilder.withMagic(PcapBuilder.MAGIC_PCAPNG).build()));
    assertTrue(e.getMessage().contains("pcapng"));
}

@Test
void 지원하지_않는_링크타입이면_즉시_실패한다() {
    // 부분 결과를 내면 "위반 0건" 이 안전으로 오독된다.
    assertThrows(PcapException.class, () -> PcapReader.read(PcapBuilder.withLinkType(228).build()));
}

@Test
void 글로벌_헤더가_잘리면_즉시_실패한다() {
    assertThrows(PcapException.class, () -> PcapReader.read(new byte[10]));
    assertThrows(PcapException.class, () -> PcapReader.read(new byte[0]));
}

@Test
void 패킷_데이터가_잘리면_즉시_실패한다() {
    byte[] full = PcapBuilder.ethernet().packet(1, 0, new byte[]{1, 2, 3, 4}).build();
    assertThrows(PcapException.class, () -> PcapReader.read(Arrays.copyOf(full, full.length - 2)));
}

@Test
void 선언_길이가_비정상적으로_크면_OOM이_아니라_예외다() {
    // 잔여 바이트 검사가 없으면 선언 길이를 그대로 믿고 읽으러 간다.
    // 이 케이스는 양수 경로를 막는다 — 부호 비트 경로는 아래 테스트가 맡는다.
    assertThrows(PcapException.class, () -> PcapReader.read(PcapBuilder.ethernet()
        .packetWithDeclaredLength(1, 0, new byte[]{1, 2}, 0x7FFFFFFF).build()));
}

@Test
void 선언_길이의_부호비트가_서_있어도_예외다() {
    // 0x7FFFFFFF 는 양수라 부호 비트 경로를 타지 않는다.
    // 마스킹이 없으면 0xFFFFFFFF 는 -1 로 읽혀 잔여 검사를 통과하고 new byte[-1] 에서 터진다.
    assertThrows(PcapException.class, () -> PcapReader.read(PcapBuilder.ethernet()
        .packetWithDeclaredLength(1, 0, new byte[]{1, 2}, 0xFFFFFFFF).build()));
}

@Test
void 타임스탬프의_부호비트가_서_있어도_미래_시각으로_읽는다() {
    // ts_sec 은 2038 년 이후 부호 비트가 선다. 마스킹하지 않으면 1901 년으로 읽혀
    // Observation.at 이 통째로 뒤집힌다 — 리포트의 시간축이 무의미해진다.
    // 0xFFFFFFFF 는 int 로 -1 이다. 마스킹하면 4,294,967,295 초 = 2106 년.
    CapturedPacket p = PcapReader.read(PcapBuilder.ethernet()
        .packet(0xFFFFFFFF, 0, new byte[]{1, 2}).build()).get(0);
    assertEquals(Instant.ofEpochSecond(4_294_967_295L), p.at());
}
```

- [ ] **Step 3: 실패 확인**

Run: `mvn -pl pcap test`
Expected: 컴파일 실패

- [ ] **Step 4: 구현**

```java
public record CapturedPacket(Instant at, byte[] data, long originalLength) {
    /** incl_len < orig_len — 캡처가 잘렸다. 하류는 이 패킷을 온전한 것으로 취급하면 안 된다. */
    public boolean truncated() { return data.length < originalLength; }
}
```

`truncated`는 레코드 컴포넌트가 아니라 파생 메서드다. `@param truncated`로 적으면 doclint가 없는 파라미터라고 잡는다.

`originalLength`가 `int`가 아니라 `long`인 이유 — `orig_len`은 unsigned 32비트다. `int`로 좁히면 `0xFFFFFFFF`인 파일에서 `-1`이 되어 `truncated()`가 false를 내고, 잘린 캡처가 온전한 것으로 하류에 흘러간다.

`PcapReader`는 **`public final class`**, `read`는 **`public static`**이다. `PcapException`은 **`public class PcapException extends RuntimeException`**이며 생성자는 `public PcapException(String)`이다. **패키지-프라이빗으로 두면 청크 2는 전부 초록으로 끝난 뒤 Task 13·14에서야 "not public / cannot be accessed"로 터진다** — 청크 2의 소비자가 전부 같은 패키지라 여기서는 드러나지 않는다. 예외를 checked로 만들면 `FrameDecoder`·`Pipeline`·`Huginn.run`의 시그니처와 Task 14의 종료 코드 배선이 전부 달라지므로 unchecked로 못박는다.

`PcapReader`:
- `read(byte[])` 하나만 노출한다. 1차는 전체 로딩만 하고 스트리밍은 범위 밖이다. `read(Path)`는 소비자가 없어 두지 않는다 — `Huginn.run`이 `Files.readAllBytes`로 읽어 `Pipeline.run(byte[], String)`에 넘긴다.
- **입력이 24바이트(글로벌 헤더)보다 짧으면 먼저 `PcapException`**을 던진다. 이 검사가 없으면 `new byte[0]`이 마스킹 이전에 `BufferUnderflowException`으로 터진다.
- 매직을 네 가지로 **식별해서** 거부한다 — `0xA1B2C3D4`만 진행, `0xD4C3B2A1`은 "빅엔디언", `0xA1B23C4D`는 "나노초 해상도", `0x0A0D0D0A`는 "pcapng"라고 메시지에 적는다.
- 링크타입 1(Ethernet)만 허용.
- `ts_sec`·`ts_usec`·`incl_len`·`orig_len`은 **모두** `& 0xFFFFFFFFL`로 unsigned 해석한다. `incl_len`이 잔여 바이트 수를 넘으면 `PcapException`.

- [ ] **Step 5: 통과 확인**

Run: `mvn -pl pcap test`
Expected: `Tests run: 13, Failures: 0`

- [ ] **Step 6: 커밋**

```bash
git add pcap/src
git commit -m "feat: pcap 리더와 합성 빌더 — 포맷 변형을 원인과 함께 거부한다"
```

---

### Task 7: `FrameDecoder` — Ethernet → IPv4 → TCP

**Files:**
- Create: `pcap/src/main/java/dev/krillin/huginn/pcap/TcpSegment.java`
- Create: `pcap/src/main/java/dev/krillin/huginn/pcap/FrameDecoder.java`
- Create: `pcap/src/main/java/dev/krillin/huginn/pcap/DecodedFrames.java`
- Test: `pcap/src/test/java/dev/krillin/huginn/pcap/FrameDecoderTest.java`
- Modify: `pcap/src/test/java/dev/krillin/huginn/pcap/PcapBuilder.java` — 프레임 조립 헬퍼 추가

이름이 `LinkLayerDecoder`가 아닌 이유 — 링크 계층만이 아니라 네트워크(IPv4)와 전송(TCP)까지 벗겨낸다.

- [ ] **Step 1: 빌더에 프레임 조립 헬퍼 추가**

```java
/** TCP 플래그 비트. 데이터 세그먼트는 보통 ACK 만 서 있다. */
public static final int FLAG_SYN = 0x02, FLAG_ACK = 0x10;

/**
 * Ethernet(14) + IPv4(20 + options) + TCP(20 + options) 프레임을 조립한다.
 * 체크섬은 0으로 둔다 — 리더가 검증하지 않는다(손상 탐지는 이 도구의 목적이 아니다).
 *
 * @param tcpFlags   TCP 헤더 오프셋 13에 그대로 넣는다. 데이터 세그먼트는 FLAG_ACK,
 *                   클라이언트 SYN 은 FLAG_SYN, 서버 SYN+ACK 는 FLAG_SYN | FLAG_ACK.
 * @param ethPadTo   이 길이에 못 미치면 0으로 채운다. 이더넷 최소 프레임(60) 재현용.
 */
public static byte[] ethernetIpv4Tcp(String srcIp, int srcPort, String dstIp, int dstPort,
                              long seq, int tcpFlags, byte[] payload,
                              int ipOptionBytes, int tcpOptionBytes, int ethPadTo) { ... }

/**
 * VLAN 태그를 끼운 변형.
 *
 * @param vlanIds 바깥에서 안쪽 순서. 하나면 802.1Q, 둘이면 QinQ 이중 태그다.
 *                이중 태그를 만들 수 없으면 "if 가 아니라 반복" 규칙에 테스트가 붙지 않는다.
 */
public static byte[] vlanTagged(String srcIp, int srcPort, String dstIp, int dstPort,
                         long seq, byte[] payload, int... vlanIds) { ... }

/** UDP 프레임 — 대상이 아님을 확인하는 용도. */
public static byte[] ethernetIpv4Udp(String srcIp, int srcPort, String dstIp, int dstPort, byte[] payload) { ... }

/**
 * 단편화된 IPv4. protocol 은 6(TCP)이고, **fragmentOffset == 0 이면 정상적인 20바이트 TCP
 * 헤더(dataOffset 5, 4-튜플, seq, FLAG_ACK)를 채운다.**
 * <p>포트·seq 인자가 없으면 IP 페이로드가 0으로 차서 dataOffset == 0 이 되고,
 * MF·offset 검사를 **아예 구현하지 않은** 디코더도 `dataOffset < 5` 규칙에 걸려 똑같이
 * skipped 를 낸다 — 두 단편화 테스트가 초록으로 통과하면서 아무것도 시험하지 않게 된다.
 *
 * @param fragmentOffset 0 이 아니면 TCP 헤더가 아예 없다(그 자리부터 페이로드다).
 * @param moreFragments  MF 플래그. offset == 0 이라도 MF 가 서 있으면 첫 조각이라
 *                       페이로드가 뒤 조각으로 이어져 프레임 경계를 믿을 수 없다.
 */
public static byte[] ipv4Fragment(String srcIp, int srcPort, String dstIp, int dstPort, long seq,
                           int fragmentOffset, boolean moreFragments, byte[] payload) { ... }

/** 임의 ethertype 프레임 — ARP(0x0806) 등 IPv4 가 아닌 것을 만든다. */
public static byte[] ethernetWithEthertype(int ethertype, byte[] body) { ... }
```

구현 지침: IPv4 헤더의 `totalLength`는 **IP 헤더부터 페이로드 끝까지**의 실제 길이를 적는다(패딩 제외). IHL·dataOffset은 옵션 바이트 수에 맞춰 계산한다.

- [ ] **Step 2: 실패하는 테스트 작성**

테스트 헬퍼 둘:
- `private List<CapturedPacket> readAsPackets(byte[]... frames)` — 프레임들을 pcap 으로 감싸 `PcapReader.read`에 태운다.
- `private List<CapturedPacket> readAsSnappedPackets(byte[] frame, int originalLength)` — snaplen 절단 재현. `incl_len < orig_len`인 패킷으로 감싼다.
- `private TcpSegment decodeSingle(byte[] frame)` — `FrameDecoder.decode(readAsPackets(frame))`의 유일한 세그먼트를 돌려준다.

```java
@Test
void TCP_세그먼트의_4튜플과_페이로드를_뽑는다() { /* 10.0.1.20:40000 → 10.0.2.11:502, seq 1000, "abc" */ }

@Test
void 이더넷_패딩이_페이로드에_섞이지_않는다() {
    // 짧은 프레임은 60바이트로 패딩된다. 캡처 잔여 바이트로 자르면 0바이트가 스트림에 섞이고,
    // 그 0들이 응용 계층 프레임의 길이 필드 경계 탐색을 어긋나게 한다.
    byte[] frame = PcapBuilder.ethernetIpv4Tcp("10.0.1.20", 40000, "10.0.2.11", 502,
        1000, PcapBuilder.FLAG_ACK, new byte[]{1, 2, 3}, 0, 0, /* ethPadTo */ 60);
    TcpSegment s = decodeSingle(frame);
    assertArrayEquals(new byte[]{1, 2, 3}, s.payload());
}

@Test
void SYN과_ACK_비트를_세그먼트에_싣는다() {
    // 청크 3 의 클라이언트 판정이 이 두 비트에 전적으로 기댄다. 여기서 싣지 않으면
    // 조립기의 sawSynOnly 가 아예 계산 불가능하다.
    TcpSegment syn = decodeSingle(PcapBuilder.ethernetIpv4Tcp("10.0.1.20", 40000,
        "10.0.2.11", 502, 1000, PcapBuilder.FLAG_SYN, new byte[0], 0, 0, 0));
    assertTrue(syn.syn());
    assertFalse(syn.ack(), "클라이언트 SYN 에는 ACK 가 없다");

    TcpSegment synAck = decodeSingle(PcapBuilder.ethernetIpv4Tcp("10.0.2.11", 502,
        "10.0.1.20", 40000, 7000, PcapBuilder.FLAG_SYN | PcapBuilder.FLAG_ACK, new byte[0], 0, 0, 0));
    assertTrue(synAck.syn());
    assertTrue(synAck.ack(), "SYN+ACK 를 SYN 과 구별하지 못하면 서버가 클라이언트로 읽힌다");
}

@Test
void IP_옵션이_있어도_헤더_길이를_보고_페이로드를_찾는다() { /* ipOptionBytes = 4 */ }

@Test
void TCP_옵션이_있어도_데이터_오프셋을_보고_페이로드를_찾는다() { /* tcpOptionBytes = 12 */ }

@Test
void VLAN_태그가_붙어도_해독한다() {
    // 산업망에서는 VLAN 이 오히려 기본이다. 조용히 건너뛰면
    // VLAN 캡처 전체가 사라지고 "위반 0건" 이 나온다 — 설계 §7 이 위험하다고 못박은 상황이다.
    // vlanIds 하나 → 802.1Q.
}

@Test
void 이중_VLAN_태그도_벗긴다() {
    // QinQ. if 한 번으로 벗기면 안쪽 태그가 남아 ethertype 자리에서 0x8100 을 읽고
    // IPv4 가 아니라고 건너뛴다 — 캡처가 통째로 사라진다.
    byte[] frame = PcapBuilder.vlanTagged("10.0.1.20", 40000, "10.0.2.11", 502,
        1000, new byte[]{1, 2, 3}, 100, 200);
    assertArrayEquals(new byte[]{1, 2, 3}, decodeSingle(frame).payload());
}

@Test
void IPv4가_아니면_대상_외로_센다() { /* ethernetWithEthertype(0x0806, ...) — ARP */ }

@Test
void TCP가_아니면_대상_외로_센다() { /* UDP */ }

@Test
void 단편화된_조각은_대상_외로_센다() {
    // fragment offset != 0 인 조각에는 TCP 헤더가 없다. 있다고 가정하고 파싱하면 쓰레기를 읽는다.
    // 페이로드는 유효한 TCP 헤더처럼 보이는 바이트로 채운다 — 0 으로 채우면 offset 검사를
    // 지운 구현도 dataOffset < 5 에 걸려 같은 답을 내고 테스트가 공허해진다.
}

@Test
void MF가_선_첫_조각도_대상_외다() {
    // offset == 0 이라 TCP 헤더는 있지만 페이로드가 뒤 조각으로 이어진다.
    // 온전한 세그먼트로 취급하면 응용 계층 길이 필드가 실제보다 길어 다음 경계가 어긋난다.
    // TCP 헤더가 온전하므로 MF 검사를 빼면 유효 세그먼트가 나와 skipped == 0 이 된다 —
    // 정확히 그 이유로 실패하는 테스트다.
    byte[] frame = PcapBuilder.ipv4Fragment("10.0.1.20", 40000, "10.0.2.11", 502, 1000,
        /* fragmentOffset */ 0, /* moreFragments */ true, new byte[]{1, 2, 3});
    DecodedFrames d = FrameDecoder.decode(readAsPackets(frame));
    assertEquals(1, d.skipped());
    assertTrue(d.segments().isEmpty());
}

@Test
void 헤더보다_짧은_프레임은_예외가_아니라_대상_외다() {
    // IndexOutOfBoundsException 이 아니라 정의된 동작이어야 한다.
}

@Test
void 헤더는_온전한데_페이로드가_잘리면_절단으로_표시하고_버리지_않는다() {
    // snaplen 절단의 정상 경로다. 유도 길이만큼 자르려 들면 IndexOutOfBoundsException 이 난다.
    // Task 6 의 절단 픽스처는 이더넷 헤더보다 짧아 이 경로에 닿지 않는다.
}

@Test
void pcap_수준_절단이_세그먼트_절단으로_전파된다() {
    // truncated 는 CapturedPacket.truncated() 와 잘라내기의 OR 인데, 다른 테스트는
    // 전부 incl_len == orig_len 이라 앞 절반을 한 번도 시험하지 않는다.
    // CapturedPacket.truncated() 를 통째로 무시하는 구현이 나머지를 전부 통과하고,
    // 그러면 tcpdump -s 96 캡처에서 청크 3 의 절단 관찰이 조용히 무력해진다.
    byte[] frame = PcapBuilder.ethernetIpv4Tcp("10.0.1.20", 40000, "10.0.2.11", 502,
        1000, PcapBuilder.FLAG_ACK, new byte[]{1, 2, 3}, 0, 0, 0);
    TcpSegment s = FrameDecoder.decode(readAsSnappedPackets(frame, 1500)).segments().get(0);
    assertTrue(s.truncated(), "페이로드는 온전해도 캡처가 잘렸으면 절단이다");
    assertArrayEquals(new byte[]{1, 2, 3}, s.payload());
}

@Test
void 대상_외_패킷_수를_보고한다() {
    // "아무것도 못 읽었다" 를 드러내려면 건너뛴 수를 알아야 한다.
    DecodedFrames d = FrameDecoder.decode(readAsPackets(
        PcapBuilder.ethernetWithEthertype(0x0806, new byte[28]),                        // ARP
        PcapBuilder.ethernetIpv4Udp("10.0.1.20", 40000, "10.0.2.11", 502, new byte[]{1, 2, 3})));
    assertEquals(2, d.skipped());
    assertTrue(d.segments().isEmpty());
}
```

- [ ] **Step 3: 실패 확인**

Run: `mvn -pl pcap test`
Expected: 컴파일 실패

- [ ] **Step 4: 구현**

```java
/**
 * @param syn TCP 헤더 오프셋 13의 0x02.
 * @param ack 같은 바이트의 0x10. syn 과 **따로** 싣는다 — SYN+ACK 는 둘 다 서 있고,
 *            syn 만 보면 서버가 보낸 SYN+ACK 를 연결을 연 쪽으로 오독한다.
 *            여기는 사실만 싣고 "클라이언트"라는 해석은 청크 3이 한다.
 */
public record TcpSegment(
    Instant at, String sourceAddress, int sourcePort,
    String targetAddress, int targetPort, long sequence, byte[] payload,
    boolean truncated, boolean syn, boolean ack) {}
```

```java
/**
 * @param skipped 산업 트래픽 대상이 아니어서 건너뛴 패킷 수 — ARP 등 비IPv4·UDP·IP 단편·
 *                **헤더보다 짧은 프레임**. 페이로드만 잘린 프레임은 여기 세지 않는다.
 *                그것은 truncated 로 표시해 그대로 흘린다(같은 Step 의 구현 규칙).
 */
public record DecodedFrames(List<TcpSegment> segments, int skipped) {}
```

`FrameDecoder`는 **`public final class`**, `decode`는 **`public static`**이다 — 청크 3의 `cli`가 부른다.

**오프셋과 마스크를 전부 못박는다.** 이 층의 결함은 전부 여기서 나온다.

| 값 | 위치 |
|---|---|
| ethertype | 이더넷 오프셋 12, 2바이트 BE |
| VLAN 태그 | TPID 2 + TCI 2 = 4바이트. 다음 ethertype은 직전 ethertype 위치 + 4 |
| IHL | IP 오프셋 0의 하위 니블 × 4 |
| totalLength | IP 오프셋 2, 2바이트 BE |
| flags + fragmentOffset | IP 오프셋 6, 2바이트 BE. `MF = value & 0x2000`, `offset = value & 0x1FFF`(8바이트 단위) |
| 프로토콜 | IP 오프셋 9 |
| TCP 헤더 시작 | 이더넷 헤더 끝 + `IHL*4` |
| dataOffset | TCP 오프셋 12의 **상위** 니블 × 4 |
| 플래그 | TCP 오프셋 13. `0x02` = SYN, `0x10` = ACK |
| 출발지·목적지 IP | IP 오프셋 12·16, 각 4바이트 |
| 출발지·목적지 포트 | TCP 오프셋 0·2, 각 2바이트 BE |
| seq | TCP 오프셋 4, 4바이트 BE |

**16비트 필드는 전부 `& 0xFFFF`로 읽는다** — `ByteBuffer.getShort()`는 부호 있는 값이라 `0x8100`이 `-32512`, `0x88A8`이 `-30552`가 되어 **VLAN 비교가 거짓이 되고 캡처 전체가 사라진다.** 포트 40000도 마찬가지로 음수가 된다. 32비트 seq는 `& 0xFFFFFFFFL`.

`FrameDecoder.decode(List<CapturedPacket>) → DecodedFrames`:
- ethertype은 오프셋 12에서 읽는다. `0x0800`이면 IPv4. **`0x8100`(또는 `0x88A8`)이면 802.1Q 태그이며, 그 다음 ethertype은 오프셋 16에 있다** — 태그 4바이트 중 앞 2바이트가 이미 읽은 TPID다. 이중 태그(QinQ)가 있으므로 **`if`가 아니라 반복**으로 벗긴다(그러지 않으면 이중 태그 트래픽이 통째로 사라져 fix 의 취지가 무너진다)
- IPv4 프로토콜 6(TCP)만. **fragment offset ≠ 0 이거나 MF 플래그가 서 있으면** 건너뛴다 — 첫 조각도 페이로드가 잘려 있어 프레임 경계를 믿을 수 없다
- **`payload = totalLength − IHL*4 − dataOffset*4`** 로 길이를 유도한다. **유도 길이가 실제 남은 바이트보다 크면 있는 만큼만 잘라내고 `truncated = true`** 로 둔다(snaplen 절단의 정상 경로다). 유도 길이가 음수이거나 `IHL < 5` · `dataOffset < 5` 이면 `skipped`. **`totalLength == 0`이면 `skipped`** — 송신 호스트에서 TSO/GSO 오프로드를 켠 채 뜬 캡처에서 실제로 나오는 값이다. 유도 길이가 음수가 되어 어차피 걸리지만, 우연이 아니라 의도된 처리임을 남긴다
- **TCP 플래그는 TCP 헤더 오프셋 13 바이트에서 읽는다** — `0x02`가 `syn`, `0x10`이 `ack`
- `sequence`는 `& 0xFFFFFFFFL`
- `TcpSegment.truncated`는 **`CapturedPacket.truncated()`와 위 잘라내기 둘의 OR**다. 두 곳에서 값을 쓰므로 뒤엣것이 앞엣것을 덮어쓰지 않게 한다
- 어떤 이유로든 대상이 아니면 `skipped`를 올린다(예외를 던지지 않는다)
- **`segments`는 입력 패킷 순서를 유지한다** — Task 8의 최초 등장 순서 결정성이 이 전제 위에 선다

- [ ] **Step 5: 통과 확인**

Run: `mvn -pl pcap test`
Expected: `Tests run: 28, Failures: 0` (`PcapReaderTest` 13 + `FrameDecoderTest` 15)

- [ ] **Step 6: 커밋**

```bash
git add pcap/src
git commit -m "feat: 프레임 디코드 — VLAN 대응, 페이로드 길이를 IP 헤더에서 유도"
```

---

### Task 8: `TcpStreamAssembler`

**Files:**
- Create: `pcap/src/main/java/dev/krillin/huginn/pcap/TcpStream.java`
- Create: `pcap/src/main/java/dev/krillin/huginn/pcap/TcpStreamAssembler.java`
- Test: `pcap/src/test/java/dev/krillin/huginn/pcap/TcpStreamAssemblerTest.java`

- [ ] **Step 1: 실패하는 테스트 작성**

테스트 헬퍼 여섯. **고정 4-tuple 축약형만으로는 방향·절단·열거 순서·결정성 테스트 넷을 아예 쓸 수 없다** — 전체형과 목록 반환형이 함께 있어야 한다.

```java
private static final String A = "10.0.1.20", B = "10.0.2.11";

/** 전체형. syn=false·ack=true 인 데이터 세그먼트. at 은 seq 를 밀리초로 환산해 넣는다. */
private TcpSegment seg(String src, int sport, String dst, int dport,
                       long seq, String payload, boolean truncated) { ... }

/** 축약형 — A:40000 → B:502 고정, truncated=false. */
private TcpSegment seg(long seq, String payload) { return seg(A, 40000, B, 502, seq, payload, false); }

/** 같은 고정 4-tuple 의 길이 0 세그먼트, syn=true·ack=false. */
private TcpSegment syn(long seq) { ... }

/** 같은 고정 4-tuple 의 길이 0 세그먼트, syn=true·ack=true. */
private TcpSegment synAck(long seq) { ... }

private List<TcpStream> assembleAll(TcpSegment... segs) { return TcpStreamAssembler.assemble(List.of(segs)); }

private TcpStream assemble(TcpSegment... segs) { return assembleAll(segs).get(0); }
```

```java
@Test
void 순서대로_온_세그먼트를_이어붙인다() { /* seq 100 "abc", seq 103 "def" → "abcdef" */ }

@Test
void 순서가_뒤바뀌어도_seq로_정렬한다() {
    // at 도 함께 못박는다 — "입력 순서상 첫 번째" 로 구현하면 여기서 뒤집힌다.
    TcpStream s = assemble(seg(103, "def"), seg(100, "abc"));
    assertArrayEquals("abcdef".getBytes(), s.contiguousPrefix());
    assertEquals(seg(100, "abc").at(), s.at(), "가장 이른 시각이지 입력 순서상 첫 번째가 아니다");
}

@Test
void SYN을_보면_바이트는_버리되_sawSynOnly를_기록한다() {
    // 길이 0 세그먼트를 통째로 버리면 연결을 연 쪽을 확정할 유일한 신호가 사라진다.
    TcpStream s = assemble(syn(1000), seg(1001, "abc"));
    assertTrue(s.sawSynOnly());
    // 그리고 SYN 의 seq 가 base 후보로 새어 들어가면 안 된다. 들어가면 base=1000 이 되어
    // 데이터가 오프셋 1 에 놓이고 1바이트 갭이 난다 — 길이 0 제외 규칙이 무력화된다.
    assertFalse(s.hasGap());
    assertArrayEquals("abc".getBytes(), s.contiguousPrefix());
}

@Test
void SYN_ACK는_sawSynOnly가_아니다() {
    // SYN+ACK 도 SYN 비트가 서 있다. syn 만 보면 서버 방향에도 플래그가 서고,
    // 핸드셰이크가 잡힌 모든 대화에서 양쪽이 같아져 청크 3 의 1순위 근거가 무력해진다.
    assertFalse(assemble(synAck(7000), seg(7001, "abc")).sawSynOnly());
}

@Test
void SYN만_있고_데이터가_없는_스트림도_정의된_값을_낸다() {
    // base seq 후보가 하나도 없다. 예외가 아니라 빈 스트림이어야 한다.
    TcpStream s = assemble(syn(1000));
    assertTrue(s.sawSynOnly());
    assertEquals(0, s.contiguousPrefix().length);
    assertFalse(s.hasGap());
    assertEquals(syn(1000).at(), s.at(), "at 후보가 없으면 null 이 되어서는 안 된다");
}

@Test
void 길이_0_세그먼트는_조립에서_제외한다() {
    // SYN 은 seq 를 1 소비한다. 제외하지 않으면 핸드셰이크가 잡힌 모든 스트림이
    // 1바이트 갭 → 전량 UNDECIDABLE 이 된다.
    TcpStream s = assemble(seg(1000, ""), seg(1001, "abc"));
    assertFalse(s.hasGap());
    assertArrayEquals("abc".getBytes(), s.contiguousPrefix());
}

@Test
void 방향마다_별개_스트림이다() {
    List<TcpStream> streams = assembleAll(
        seg(A, 40000, B, 502, 100, "req", false),
        seg(B, 502, A, 40000, 7000, "res", false));
    assertEquals(2, streams.size());
}

@Test
void 갭이_있으면_그_지점부터_UNDECIDABLE이다() {
    // 조용히 이어붙이면 프레임 경계가 어긋나 엉뚱한 함수코드를 읽는다.
    TcpStream s = assemble(seg(100, "abc"), seg(200, "xyz"));
    assertTrue(s.hasGap());
    assertArrayEquals("abc".getBytes(), s.contiguousPrefix());
}

@Test
void 캡처가_대화_중간부터_시작해도_최소_seq를_기준으로_삼는다() { /* 첫 seq 가 500000 이어도 갭 아님 */ }

@Test
void 완전_중복_세그먼트는_한_번만_반영한다() { /* 같은 seq, 같은 내용 두 번 */ }

@Test
void 겹치는_재전송은_먼저_온_바이트가_이긴다() {
    // 나중 세그먼트로 앞 내용을 덮어쓸 수 있으면 재전송 위장으로 판정을 속일 수 있다.
    // base=100. 첫 세그먼트가 오프셋 0~4, 둘째는 2~6 을 차지한다.
    // 2·3·4 는 이미 찼으므로 지고, 5·6 만 X 가 된다 → 7바이트.
    TcpStream s = assemble(seg(100, "abcde"), seg(102, "XXXXX"));
    assertArrayEquals("abcdeXX".getBytes(), s.contiguousPrefix());
}

@Test
void 절단된_세그먼트가_있으면_스트림을_절단으로_표시한다() {
    assertTrue(assemble(seg(A, 40000, B, 502, 100, "abc", /* truncated */ true)).truncated());
}

@Test
void 스트림_열거_순서는_최초_등장_순서다() {
    // HashMap 이면 리포트가 비결정적이 된다. 비결정성의 발원지가 이 층이다.
    List<TcpStream> streams = assembleAll(
        seg(B, 502, A, 40000, 7000, "res", false),      // 이쪽이 먼저 등장
        seg(A, 40000, B, 502, 100, "req", false));
    assertEquals(502, streams.get(0).sourcePort());
}

@Test
void 같은_입력에_같은_스트림_목록이_나온다() {
    // TcpStream 은 byte[] 컴포넌트를 가진 record 라 자동 생성 equals 가 배열을 **동등성이 아니라
    // 동일성**으로 비교한다. assertEquals(assemble(x), assemble(x)) 는 항상 실패한다.
    // 4-tuple 순서를 먼저 비교하고 바이트는 assertArrayEquals 로 따로 본다.
    TcpSegment[] input = {
        seg(A, 40000, B, 502, 100, "abc", false),
        seg(B, 502, A, 40000, 7000, "res", false),
        seg(A, 40000, B, 502, 103, "def", false)};
    List<TcpStream> a = assembleAll(input);
    List<TcpStream> b = assembleAll(input);
    assertEquals(2, a.size(), "스트림이 하나뿐이면 아래 비교가 자명하게 통과해 아무것도 검증하지 못한다");
    assertEquals(a.stream().map(TcpStream::sourcePort).toList(),
                 b.stream().map(TcpStream::sourcePort).toList());
    for (int i = 0; i < a.size(); i++)
        assertArrayEquals(a.get(i).contiguousPrefix(), b.get(i).contiguousPrefix());
}
```

- [ ] **Step 2: 실패 확인**

Run: `mvn -pl pcap test`
Expected: 컴파일 실패

- [ ] **Step 3: 구현**

```java
/**
 * 한 방향의 재조립된 바이트 흐름.
 *
 * @param at         이 방향에서 관찰된 세그먼트 중 **가장 이른 at**. 입력 순서가 아니라 시각이 기준이다 —
 *                   Observation.at 이 이 값에서 오므로 "입력 순서상 첫 번째" 로 읽으면
 *                   순서가 뒤바뀐 캡처에서 리포트의 시각이 뒤집힌다.
 * @param truncated  이 방향의 세그먼트 중 하나라도 절단됐으면 true. 스트림 전체를 온전한 것으로 취급하면 안 된다.
 * @param sawSynOnly 이 방향에서 **SYN 은 서 있고 ACK 는 서 있지 않은** 세그먼트를 봤다.
 *                   그런 세그먼트는 연결을 연 쪽만 보낸다. SYN+ACK 는 여기 해당하지 않는다.
 */
public record TcpStream(
    Instant at, String sourceAddress, int sourcePort, String targetAddress, int targetPort,
    byte[] contiguousPrefix, boolean hasGap, boolean truncated, boolean sawSynOnly) {}
```

`TcpStreamAssembler`는 **`public final class`**, `assemble`은 **`public static`**이다 — 청크 3의 `cli`가 부른다.

`TcpStreamAssembler.assemble(List<TcpSegment>) → List<TcpStream>`:
- 키는 `(srcAddr, srcPort, dstAddr, dstPort)` — 방향이 다르면 다른 키다
- **`LinkedHashMap`** 으로 모아 최초 등장 순서를 유지한다
- 길이 0 세그먼트는 **바이트를 버린다.** `syn && !ack`이면 그 방향의 키를 등록하고 `sawSynOnly`를 세운다. 그 외 길이 0 세그먼트(순수 ACK·FIN·SYN+ACK)는 **키 등록도 하지 않는다**
- `truncated`는 **그 방향 세그먼트 중 하나라도 절단됐으면** true. 절단된 세그먼트의 (짧은) 페이로드도 `contiguousPrefix`에 그대로 기여한다 — 어차피 뒤가 갭이므로 버리면 `contiguousPrefix`만 짧아질 뿐 얻는 게 없다
- **base seq는 바이트를 기여하는(길이 > 0) 세그먼트 중 최소 seq다.** SYN 은 키와 `sawSynOnly`만 남기고 **base 후보가 되지 않는다** — 되면 SYN(seq n)이 base가 되어 첫 데이터(seq n+1)가 오프셋 1에 놓이고, 길이 0 제외 규칙이 막으려던 1바이트 갭이 그대로 되살아난다
- 바이트를 기여하는 세그먼트가 하나도 없으면(SYN만 잡힌 스트림) `contiguousPrefix`는 빈 배열, `hasGap`은 false다
- **`at`은 그 방향에 키를 등록시킨 세그먼트 중 가장 이른 시각이다 — `syn && !ack`인 SYN도 후보다.** 키를 등록하지 않는 세그먼트(순수 ACK·FIN·SYN+ACK)는 `at` 후보도 아니다. base seq와 달리 여기서는 길이 0을 배제하지 않는다. 배제하면 SYN만 잡힌 스트림의 `at`이 정의되지 않는다. 대신 이 선택 때문에 `Observation.at`은 요청 프레임의 시각이 아니라 **그 방향 스트림의 시작 시각**이 된다 — Task 2의 javadoc이 그렇게 적혀 있어야 한다
- **seq 범위 전체를 배열로 할당하지 않는다.** base가 100인데 잡음 세그먼트 하나가 seq 3,000,000,000이면 OOM이 난다. 정렬된 세그먼트를 순회하며 첫 갭에서 멈추므로 필요한 만큼만 이어붙이면 된다
- seq 순으로 이어붙이되 **이미 채워진 오프셋은 덮어쓰지 않는다**(first-wins). **정렬은 stable해야 한다** — seq가 같고 내용이 다른 쌍에서 입력 순서가 이겨야 재전송 위장 방어가 결정적이 된다
- 첫 갭에서 멈추고 그때까지를 `contiguousPrefix`로, `hasGap = true`로 둔다

- [ ] **Step 4: 통과 확인**

Run: `mvn -pl pcap test`
Expected: `Tests run: 42, Failures: 0` (13 + 15 + 14)

- [ ] **Step 5: 커밋**

```bash
git add pcap/src
git commit -m "feat: TCP 스트림 재조립 — SYN-without-ACK 기록, 갭 이후는 UNDECIDABLE"
```

---

## Chunk 3: Modbus 해독과 배선

이 청크의 결정 셋을 먼저 못박는다.

| 결정 | 값 | 이유 |
|---|---|---|
| MBAP 길이 필드 의미 | `length = 유닛ID(1) + PDU 길이`. **다음 프레임 = 오프셋 + 6 + length**, 유효 범위는 **2 ≤ length ≤ 254** | 오해하면 두 번째 프레임부터 전부 깨진다. 최소 PDU 는 함수코드 1바이트이므로 하한이 1이 아니라 2다 |
| 요청/응답 | **요청만 `Observation`이 된다** (설계 §5-⑤) | 응답은 출발지·목적지가 뒤집혀 있어 관찰하면 정상 통신이 전부 위반이 된다 |
| 산업 프로토콜이 아닌 대화 | 대화의 **어느 스트림에서도** 유효 프레임이 0개면 **대상 외**, 1개 이상이면 그 안의 잔여 바이트만 `UNDECIDABLE` | 그러지 않으면 SSH·HTTP가 전부 `UNDECIDABLE`로 계수되어 커버리지 지표가 캡처 구성에 지배된다 |
| 절단·갭 vs 대상 외의 우선순위 | **대상 외가 이긴다** — 대화의 어느 스트림에서도 유효 프레임이 안 나오면 절단·갭을 보지 않고 대상 외로 끝낸다 | `tcpdump -s 96` 같은 환경에서는 SSH 스트림도 전부 절단이다. 절단이 이기면 위 결정이 무력해진다 |
| 계수 단위 | **대화**(스트림이 아니라). 대상 외·해독·UNDECIDABLE 셋은 배타적이며 합이 전체 대화 수다 | 리포트가 "대화"로 적는다. 스트림으로 세면 응답 방향 스트림이 어느 칸에도 안 세여 합이 맞지 않고, "해독한 대화 6"이 6인지 12인지 알 수 없다 |

### Task 9: MBAP 프레이밍

**Files:**
- Create: `decode/src/main/java/dev/krillin/huginn/decode/ModbusFrame.java`
- Create: `decode/src/main/java/dev/krillin/huginn/decode/FramingResult.java`
- Create: `decode/src/main/java/dev/krillin/huginn/decode/ModbusFramer.java`
- Test: `decode/src/test/java/dev/krillin/huginn/decode/ModbusFramerTest.java`
- Create: `decode/src/test/java/dev/krillin/huginn/decode/ModbusFixtures.java` — Task 11·12·13·14 와 공유하는 픽스처

MBAP: 트랜잭션ID(2) · 프로토콜ID(2, **반드시 0**) · 길이(2) · 유닛ID(1) · PDU.

테스트 픽스처는 `decode/src/test/java/dev/krillin/huginn/decode/ModbusFixtures.java`에 모은다. **Task 11·12·13 은 물론 Task 14 의 `cli` E2E 도 같은 것을 쓰므로 `public final class`이고 세 메서드도 `public static`이다** — `private`이면 Task 12·13 이 `ModbusFixtures.mbap(...)`을 부르는 순간, 패키지-프라이빗이면 Task 14 가 부르는 순간 컴파일이 깨진다. (청크 2 의 `PcapBuilder` 는 `pcap` 모듈 테스트 소스라 여기서 보이지 않는다.)

```java
public final class ModbusFixtures {
    /** MBAP 한 프레임. length = 2 + pduBody.length (유닛ID 1 + 함수코드 1 + 본문). */
    public static byte[] mbap(int tid, int uid, int fc, byte[] pduBody) { ... }

    /** 시작 주소·수량을 빅엔디언 2바이트씩 이어 붙인 4바이트(함수코드는 포함하지 않는다). */
    public static byte[] pdu(int startAddress, int quantity) { ... }

    /** 프레임 여러 개를 한 스트림으로 잇는다. */
    public static byte[] concat(byte[]... parts) { ... }
}
```

- [ ] **Step 1: 실패하는 테스트 작성**

```java
@Test
void 유효한_MBAP_프레임을_뽑는다() { /* tid=1, pid=0, len=6, uid=1, fc=3, ... */ }

@Test
void 한_스트림에_연속된_프레임_여러_개를_뽑는다() {
    // 다음 프레임 시작 = 오프셋 + 6 + length. 7 + length 로 오해하면 두 번째부터 깨진다.
}

@Test
void protocolId가_0이_아니면_프레임이_아니다() { /* 포트가 502 여도 */ }

@Test
void 길이_필드가_범위를_벗어나면_프레임이_아니다() {
    // 최대 ADU 260 = MBAP 6 + 유닛 1 + PDU 253 → 상한 254.
    // 하한은 2 다 — length = 유닛ID(1) + PDU 이고 최소 PDU 는 함수코드 1바이트.
    // 1 을 허용하면 함수코드 자리에 다음 프레임의 첫 바이트를 읽는다.
    // 임의 바이너리를 Modbus 로 오인하면 미등록 쌍에서 HIGH Finding 이 만들어진다.
}

@Test
void 함수코드가_0이면_프레임이_아니다() { /* fc == 0 은 유효하지 않다 */ }

@Test
void 마지막_프레임이_잘려도_예외가_아니라_미해독_바이트다() {
    // 캡처가 프레임 중간에서 끝나는 것은 정상적인 상황이다.
}

@Test
void 프레임을_하나도_못_뽑으면_Modbus_스트림이_아니다() {
    // SSH·HTTP 등. UNDECIDABLE 이 아니라 대상 외다 — 설계 §5-⑥.
    FramingResult r = ModbusFramer.frames("SSH-2.0-OpenSSH_9.0\r\n".getBytes());
    assertFalse(r.isModbusStream());
    assertTrue(r.frames().isEmpty());
}

@Test
void 프레임_뒤의_잔여_바이트만_미해독으로_센다() {
    // 재동기화를 하지 않으므로 '프레임 사이' 라는 것은 없다 — 첫 무효 지점 이후의 잔여뿐이다.
    // 유효 프레임을 하나라도 뽑았으면 그 잔여만 UNDECIDABLE 이다.
}

@Test
void 스트림_중간부터_시작해도_재동기화하지_않는다() {
    // 프레임 경계를 찾아 앞으로 스캔하지 않는다. 오탐이 오검출보다 비싸다.
}
```

- [ ] **Step 2: 실패 확인**

Run: `mvn -pl decode -am test`
Expected: 컴파일 실패

- [ ] **Step 3: 구현**

```java
/** @param pdu 함수코드를 **뺀** 나머지 데이터. 따라서 `pdu.length == length - 2` 다. */
public record ModbusFrame(int transactionId, int unitId, int functionCode, byte[] pdu) {}
```

```java
/**
 * @param isModbusStream 유효 프레임을 한 개 이상 뽑았는가. false 면 이 스트림은 산업 트래픽이 아니라
 *                       대상 외이며, undecodedBytes 를 커버리지에 계수하지 않는다.
 */
public record FramingResult(List<ModbusFrame> frames, int undecodedBytes, boolean isModbusStream) {}
```

`ModbusFramer.frames(byte[] stream)`:
- 오프셋 0부터 시작해 재동기화하지 않는다
- 잔여 < 8이면 남은 바이트를 `undecodedBytes`로 누적하고 종료
- `protocolId != 0` 또는 `length < 2 || length > 254` 또는 `functionCode == 0`이면 그 지점부터 남은 전부를 `undecodedBytes`로 누적하고 종료
- 잔여가 `6 + length`보다 작으면(절단) 남은 바이트를 누적하고 종료
- **포트를 인자로 받지 않는다** — 프레이밍만으로 판정한다

- [ ] **Step 4: 통과 확인**

Run: `mvn -pl decode -am test`
Expected: `decode` 모듈 `Tests run: 9, Failures: 0`

- [ ] **Step 5: 커밋**

```bash
git add decode/src
git commit -m "feat: MBAP 프레이밍 — 포트가 아니라 프레이밍으로 판정한다"
```

---

### Task 10: 함수코드 → `Access`

**Files:**
- Create: `decode/src/main/java/dev/krillin/huginn/decode/ModbusAccess.java`
- Test: `decode/src/test/java/dev/krillin/huginn/decode/ModbusAccessTest.java`

- [ ] **Step 1: 실패하는 테스트 작성**

```java
@ParameterizedTest @ValueSource(ints = {1, 2, 3, 4, 7, 11, 12, 17, 20, 24})
void 읽기_함수코드(int fc) { assertEquals(Access.READ, ModbusAccess.of(fc)); }

@ParameterizedTest @ValueSource(ints = {5, 6, 15, 16, 21, 22, 23})
void 쓰기_함수코드(int fc) {
    // 21(Write File Record)이 빠지면 미등록 장비의 파일 레코드 쓰기가 보고되지 않는다.
    assertEquals(Access.WRITE, ModbusAccess.of(fc));
}

@Test
void 진단은_제어로_본다() {
    // 서브함수에 Restart Communications / Force Listen Only 가 있어 보수적으로 분류한다.
    // 대부분의 서브함수는 카운터 읽기이므로 과대분류인 면이 있다.
    assertEquals(Access.CONTROL, ModbusAccess.of(8));
}

@Test
void 캡슐화_전송은_UNDECIDABLE이다() {
    // 43 의 의미는 MEI Type 이 정한다 — MEI 14 는 Read Device Identification(읽기),
    // MEI 13(CANopen)은 읽기·쓰기를 모두 실어 나른다. MEI 를 보지 않고 CONTROL 로 올리면
    // 정상적인 장치식별 조회가 최고 심각도 위반이 된다.
    assertEquals(Access.UNDECIDABLE, ModbusAccess.of(43));
}

@ParameterizedTest @ValueSource(ints = {0, 9, 13, 99, 0x83})
void 정의되지_않은_함수코드는_UNDECIDABLE이다(int fc) {
    // 0x83 은 FC 3 의 예외 응답이다. 설계 §5-⑤ 로 응답은 관찰하지 않지만,
    // 단방향 캡처에서 새어 들어와도 위반으로 단정하지 않도록 여기서 고정한다.
    assertEquals(Access.UNDECIDABLE, ModbusAccess.of(fc));
}
```

- [ ] **Step 2: 실패 확인**

Run: `mvn -pl decode -am test`
Expected: 컴파일 실패

- [ ] **Step 3: 구현**

`switch` 하드코딩 대신 상수 테이블(`Map<Integer, Access>`)로 둔다 — 함수코드 목록이 곧 문서가 되고, 2차 S7comm에서 같은 형태를 재사용한다.

- [ ] **Step 4: 통과 확인**

Run: `mvn -pl decode -am test`
Expected: `decode` 모듈 `Tests run: 33, Failures: 0` (프레이밍 9 + 매핑 24)

> `@ParameterizedTest`는 **호출 하나가 테스트 하나**로 집계된다 — 10(READ) + 7(WRITE) + 1(진단) + 1(캡슐화) + 5(미정의) = 24.

- [ ] **Step 5: 커밋**

```bash
git add decode/src
git commit -m "feat: Modbus 함수코드 → Access, 43은 MEI를 보지 않으므로 UNDECIDABLE"
```

---

### Task 11: `objectRef` 생성

**Files:**
- Create: `decode/src/main/java/dev/krillin/huginn/decode/ModbusObjectRef.java`
- Test: `decode/src/test/java/dev/krillin/huginn/decode/ModbusObjectRefTest.java`

`Observation.objectRef`는 근거 표시용이며 판정에는 쓰지 않는다. 그래도 리포트에서 "무엇을 건드렸는가"가 없으면 운영자가 조치할 수 없다.

`pdu(...)`는 Task 9 의 `ModbusFixtures.pdu`를 쓴다 — 아래 테스트는 `import static dev.krillin.huginn.decode.ModbusFixtures.pdu;`로 한정 없이 부른다.

- [ ] **Step 1: 실패하는 테스트 작성**

```java
@Test
void 코일_읽기는_코일_주소로_표기한다() {
    // FC 1, 시작 주소 0 → "coil:1"  (와이어 주소 0 이 1번 코일)
    assertEquals("coil:1", ModbusObjectRef.of(1, pdu(0x0000, 0x0008)));
}

@Test
void 홀딩_레지스터_읽기는_4만번대로_표기한다() {
    // FC 3, 시작 주소 0 → "holding:40001"
    assertEquals("holding:40001", ModbusObjectRef.of(3, pdu(0x0000, 0x0002)));
}

@Test
void 입력_레지스터는_3만번대다() { /* FC 4, 주소 9 → "input:30010" */ }

@Test
void 이산_입력은_1만번대다() { /* FC 2, 주소 4 → "discrete:10005" */ }

@Test
void 단일_쓰기도_같은_규칙이다() { /* FC 6, 주소 99 → "holding:40100" */ }

@Test
void 시작_주소를_읽을_수_없는_함수코드는_함수코드만_적는다() {
    // FC 8(진단), 43(캡슐화) 등은 PDU 에 주소가 없다.
    assertEquals("fc:8", ModbusObjectRef.of(8, new byte[]{0x00, 0x00}));
}

@Test
void PDU가_짧아_주소를_못_읽으면_함수코드만_적는다() {
    assertEquals("fc:3", ModbusObjectRef.of(3, new byte[]{0x00}));
}
```

- [ ] **Step 2: 실패 확인**

Run: `mvn -pl decode -am test`
Expected: 컴파일 실패 — `ModbusObjectRef` 없음

- [ ] **Step 3: 구현**

객체 타입 매핑: FC 1·5·15 → `coil`(1번대), FC 2 → `discrete`(10001+), FC 4 → `input`(30001+), FC 3·6·16·22·23 → `holding`(40001+). 그 외는 `fc:<n>`.

- [ ] **Step 4: 통과 확인**

Run: `mvn -pl decode -am test`
Expected: `decode` 모듈 `Tests run: 40, Failures: 0` (33 + `ModbusObjectRefTest` 7)

- [ ] **Step 5: 커밋**

```bash
git add decode/src
git commit -m "feat: objectRef — 무엇을 건드렸는지 근거에 남긴다"
```

---

### Task 12: `ModbusShape` — PDU 형태로 요청/응답을 가른다

**Files:**
- Create: `decode/src/main/java/dev/krillin/huginn/decode/ModbusShape.java`
- Test: `decode/src/test/java/dev/krillin/huginn/decode/ModbusShapeTest.java`

**왜 필요한가.** 포트만으로 방향을 판정하면 **거울상을 원리적으로 구별할 수 없다.** "낮은 쪽이 서버"라는 전제는 낮은 쪽이 정말 리스닝 포트일 때만 참인데, 포트 번호만 보고는 확인할 방법이 없다. 조건을 좁혀도 구멍은 막히지 않고 경계 너머로 옮겨간다(Task 13 신호 표 아래 개정 이력 참조). 그래서 **프레임 구조 자체로 판정한다** — 설계 §5-①의 "포트가 아니라 프레이밍으로 판정한다"를 방향 판정에도 그대로 적용하는 것이다.

Modbus는 같은 함수코드라도 요청과 응답의 PDU 구조가 다르다. `ModbusFrame.pdu`는 함수코드를 뺀 나머지다. 아래는 **MODBUS Application Protocol Specification V1.1b3** §6.1~§6.19를 대조한 것이다.

| 함수코드 | 요청 PDU | 응답 PDU |
|---|---|---|
| 1·2 (코일·이산입력 읽기) | 주소2 + 수량2 = **4**. 수량 1~2000 | 바이트수1 + N = **1 + pdu[0]**, `pdu[0] = ⌈수량/8⌉ = 1~250` |
| 3·4 (레지스터 읽기) | 주소2 + 수량2 = **4**. 수량 1~125 | 바이트수1 + 2N = **1 + pdu[0]**, `pdu[0] = 2×수량`이라 **항상 짝수** → 길이는 항상 홀수 |
| 15·16 (다중 쓰기) | 주소2 + 수량2 + 바이트수1 + 데이터 = **5 + pdu[4]**. 최소 6(FC 15·수량 1 → 바이트수 1), FC 16의 최소는 7(바이트수 = 2N ≥ 2) | 주소2 + 수량2 = **정확히 4**(가변 필드가 없다) |
| 5·6·22 | 에코 — 요청과 응답이 **같다** | 같다 |
| 0x80 이상 | **존재할 수 없다**(§4.1: 128–255는 예외 응답 전용) | 예외코드 1바이트 = **정확히 1** |

**HIGH를 만드는 것이 정확히 FC 15·16이고, 그 둘이 길이만으로 완전히 갈린다.** 오탐 경로를 정면으로 닫는 신호다.

- [ ] **Step 1: 실패하는 테스트 작성**

```java
// 함수코드를 짝으로 파라미터화한다. 표는 4≡3, 2≡1, 15≡16 을 주장하는데
// 한쪽만 테스트하면 case 3·case 16·case 1 만 하드코딩한 구현이 전부 통과한다.

@ParameterizedTest @ValueSource(ints = {3, 4})
void 레지스터_읽기_요청은_정확히_4바이트다(int fc) {
    assertEquals(ModbusShape.REQUEST_ONLY, ModbusShape.of(fc, ModbusFixtures.pdu(0, 2)));
}

@ParameterizedTest @ValueSource(ints = {3, 4})
void 레지스터_읽기_응답은_바이트수가_짝수라_요청과_겹치지_않는다(int fc) {
    // 4바이트 응답이려면 바이트수가 3이어야 하는데 레지스터 응답의 바이트수는 항상 2N 이다.
    assertEquals(ModbusShape.RESPONSE_ONLY, ModbusShape.of(fc, new byte[]{4, 0, 1, 0, 2}));
}

@ParameterizedTest @ValueSource(ints = {15, 16})
void 다중_쓰기_응답은_정확히_4바이트다(int fc) {
    // 주소2 + 수량2, 가변 필드 없음.
    assertEquals(ModbusShape.RESPONSE_ONLY, ModbusShape.of(fc, new byte[]{0, 0, 0, 2}));
}

@Test
void FC16_요청은_4바이트가_아니다() {
    assertEquals(ModbusShape.REQUEST_ONLY, ModbusShape.of(16, new byte[]{0, 0, 0, 2, 4, 0, 1, 0, 2}));
}

@Test
void FC15_최소_요청은_6바이트다() {
    // >= 6 이라는 하한을 밟는 유일한 프레임이다 — 코일 1개 쓰기(바이트수 1).
    // FC 16 만으로는 최소가 7 이라 이 경계를 한 번도 시험하지 않는다.
    assertEquals(ModbusShape.REQUEST_ONLY, ModbusShape.of(15, new byte[]{0, 0, 0, 1, 1, (byte) 0xFF}));
}

@Test
void 바이트수가_0x80_이상이어도_부호확장하지_않는다() {
    // pdu[0]·pdu[4] 를 & 0xFF 없이 쓰면 여기서 조용히 UNKNOWN 이 된다.
    // 레지스터 125개 읽기 응답: 바이트수 250. 레지스터 123개 쓰기 요청: 바이트수 246.
    // 후자가 이 태스크의 존재 이유인 FC 16 경로다.
    assertEquals(ModbusShape.RESPONSE_ONLY,
        ModbusShape.of(3, ModbusFixtures.concat(new byte[]{(byte) 250}, new byte[250])));
    assertEquals(ModbusShape.REQUEST_ONLY,
        ModbusShape.of(16, ModbusFixtures.concat(new byte[]{0, 0, 0, 123, (byte) 246}, new byte[246])));
}

@Test
void 바이트수와_실제_길이가_어긋나면_모른다() {
    // 바이트수는 4 라는데 데이터는 2바이트. 길이 7 != 5+4.
    // `pdu.length >= 6 이면 REQUEST_ONLY` 로 축약한 구현을 걸러낸다.
    assertEquals(ModbusShape.UNKNOWN, ModbusShape.of(16, new byte[]{0, 0, 0, 2, 4, 0, 1}));
}

@Test
void 예외_응답은_요청일_수_없다() {
    // §4.1 — 128~255 는 예외 응답 전용이다. 이 행이 없으면 예외 응답만 실린
    // 서버 방향이 형태를 내지 못해 방향 판정이 통째로 침묵한다.
    assertEquals(ModbusShape.RESPONSE_ONLY, ModbusShape.of(0x83, new byte[]{0x02}));
}

@Test
void FC1_응답의_바이트수가_3이면_요청과_구별할_수_없다() {
    // 코일 응답의 바이트수는 홀수도 가능하다(17~24개 코일 → 3바이트).
    // 그때 응답 PDU 도 4바이트라 요청과 겹친다 — 단정하지 않는다.
    assertEquals(ModbusShape.UNKNOWN, ModbusShape.of(1, new byte[]{3, 0x0F, 0x0F, 0x0F}));
}

@ParameterizedTest @ValueSource(ints = {5, 6, 22})
void 에코_함수코드는_형태를_모른다(int fc) {
    // 응답이 요청의 에코다(§6.5·§6.6·§6.16). 원리적으로 구별할 수 없다.
    assertEquals(ModbusShape.UNKNOWN, ModbusShape.of(fc, new byte[]{0, 0, 0, 1, 0, 2}));
}

@Test
void 매핑에_없는_함수코드는_형태를_모른다() {
    assertEquals(ModbusShape.UNKNOWN, ModbusShape.of(43, new byte[]{14, 1, 0}));
}

@Test
void 짧은_PDU에도_예외가_아니라_UNKNOWN이다() {
    // pdu[4] 를 보기 전에 길이를 먼저 확인해야 한다.
    assertEquals(ModbusShape.UNKNOWN, ModbusShape.of(16, new byte[]{0, 0}));
    assertEquals(ModbusShape.UNKNOWN, ModbusShape.of(3, new byte[0]));
}

@Test
void 스트림에_두_형태가_섞이면_방향을_모른다() {
    // 재조립이 어긋났거나 캡처가 섞였다. 다수결로 밀어붙이지 않는다.
    assertEquals(ModbusShape.UNKNOWN, ModbusShape.ofStream(List.of(
        new ModbusFrame(1, 1, 3, ModbusFixtures.pdu(0, 2)),          // REQUEST_ONLY
        new ModbusFrame(2, 1, 3, new byte[]{4, 0, 1, 0, 2}))));      // RESPONSE_ONLY
}

@Test
void 형태를_아는_프레임이_하나도_없으면_모른다() {
    assertEquals(ModbusShape.UNKNOWN, ModbusShape.ofStream(List.of(
        new ModbusFrame(1, 1, 6, ModbusFixtures.pdu(0, 1)))));
}

@Test
void 빈_목록도_모른다() {
    // 캡처에 없는 방향은 프레임 0개다. Task 13 의 단방향 캡처 판정이 전부 이 값에 기댄다.
    assertEquals(ModbusShape.UNKNOWN, ModbusShape.ofStream(List.of()));
}

@Test
void 아는_프레임이_하나라도_있고_충돌이_없으면_그_형태다() {
    assertEquals(ModbusShape.REQUEST_ONLY, ModbusShape.ofStream(List.of(
        new ModbusFrame(1, 1, 6, ModbusFixtures.pdu(0, 1)),          // UNKNOWN
        new ModbusFrame(2, 1, 16, new byte[]{0, 0, 0, 2, 4, 0, 1, 0, 2}))));
}
```

- [ ] **Step 2: 실패 확인**

Run: `mvn -pl decode -am test`
Expected: 컴파일 실패 — `ModbusShape`·`ModbusShape.REQUEST_ONLY` 심볼 없음

- [ ] **Step 3: 구현**

```java
/** 한 프레임 또는 한 방향이 요청인지 응답인지. 단정할 수 없으면 UNKNOWN 이다. */
public enum ModbusShape { REQUEST_ONLY, RESPONSE_ONLY, UNKNOWN }
```

`ModbusShape`는 **`public enum`**, `of`·`ofStream`은 **`public static`**이다 — Task 13의 `ModbusObserver`가 부른다(같은 패키지지만 계약이므로 일관되게 둔다).

`ModbusShape.of(int functionCode, byte[] pdu)` — 아래에 걸리지 않으면 전부 `UNKNOWN`이다. **애매하면 UNKNOWN이다. 단정이 오검출보다 비싸다.**

| 조건 | 결과 |
|---|---|
| `u(functionCode) >= 0x80` 이고 `pdu.length == 1` | `RESPONSE_ONLY` |
| FC 3·4 이고 `pdu.length == 4` | `REQUEST_ONLY` |
| FC 3·4 이고 **`pdu.length >= 1`** 이고 `pdu.length == 1 + u(pdu[0])` 이고 `u(pdu[0])`이 짝수 | `RESPONSE_ONLY` |
| FC 1·2 이고 `pdu.length == 4` 이고 `u(pdu[0]) != 3` | `REQUEST_ONLY` |
| FC 1·2 이고 **`pdu.length >= 1`** 이고 `pdu.length != 4` 이고 `pdu.length == 1 + u(pdu[0])` | `RESPONSE_ONLY` |
| FC 15·16 이고 `pdu.length == 4` | `RESPONSE_ONLY` |
| FC 15·16 이고 `pdu.length >= 6` 이고 `pdu.length == 5 + u(pdu[4])` | `REQUEST_ONLY` |

`u(b)`는 `b & 0xFF`다. **`u()`를 빠뜨리면 조용히 실패한다** — 레지스터 123개를 쓰는 FC 16 요청은 `pdu[4] == 246`이고, 부호 확장되면 `5 + (−10) = −5`가 되어 `REQUEST_ONLY`가 아니라 `UNKNOWN`이 된다. **이 태스크가 존재하는 이유인 FC 16 경로에서 신호가 침묵한다.** 바이트수는 최대 250까지 간다.

**`pdu.length >= 1` 가드가 표에 있어야 한다.** `pdu.length != 4`는 가드가 아니다 — Java는 `==`의 우변을 무조건 평가하므로 빈 PDU에서 `pdu[0]`이 `ArrayIndexOutOfBoundsException`을 낸다. 그리고 빈 PDU는 **도달 가능하다**: 프레이머의 거부 조건이 `length < 2`이므로 MBAP length == 2(유닛ID+함수코드만)가 통과해 `pdu.length == 0`인 프레임을 만든다. (3·4행에서 `pdu.length != 4`는 짝수 조건이 이미 홀수 길이를 강제하므로 중복이라 뺐다.)

**첫 행(예외 응답)은 공짜이고 오검출이 불가능하다.** §4.1이 "128–255는 예외 응답용으로 예약"이라고 못박으므로 **0x80 이상인 함수코드는 요청일 수 없다.** 이 행이 없으면 예외 응답만 실린 서버 방향이 형태를 내지 못하고, 지원하지 않는 함수코드를 두드리는 스캐너나 잘못 설정된 폴러가 있는 캡처에서 방향 판정이 통째로 침묵한다. 부작용도 없다 — `ModbusAccess.of(0x83)`이 이미 `UNDECIDABLE`이라 방향을 특정해도 위반이 생기지 않는다.

**표에 없는 함수코드가 `UNKNOWN`인 이유**(나중에 "쉬운 승리"라며 잘못 추가하지 않도록): 5·6·22는 응답이 요청의 에코다(§6.5·§6.6·§6.16). 20은 양쪽 다 `1 + 카운트`(§6.14), 21은 명시적 에코(§6.15), 23은 요청 `9+2N`·응답 `1+2N′`으로 11바이트 이상에서 완전히 겹친다(§6.17). 43은 MEI 타입 종속이고 MEI 13(CANopen)은 읽기·쓰기를 모두 운반한다(§6.19·§6.21). 7·8·11·12는 §6.7~§6.10 제목이 "(Serial Line only)"라 Modbus/TCP 캡처에 나타나지 않는다.

`ModbusShape.ofStream(List<ModbusFrame> frames)` — 각 프레임의 형태를 모아, **`REQUEST_ONLY`와 `RESPONSE_ONLY`가 섞여 있으면 `UNKNOWN`**, 한쪽만 있으면 그 형태, 전부 `UNKNOWN`이면 `UNKNOWN`.

- [ ] **Step 4: 통과 확인**

Run: `mvn -pl decode -am test`
Expected: `decode` 모듈 `Tests run: 61, Failures: 0` (40 + `ModbusShapeTest` 21)

> `@ParameterizedTest`는 호출 하나가 테스트 하나다 — 2 + 2 + 2 + 3 = 9 회에 단일 `@Test` 12건.

- [ ] **Step 5: 커밋**

```bash
git add decode/src
git commit -m "feat: PDU 형태로 요청/응답을 가른다 — 포트는 거울상을 구별하지 못한다"
```

---

### Task 13: `ModbusObserver` — 스트림에서 요청만 관찰한다

**Files:**
- Create: `decode/src/main/java/dev/krillin/huginn/decode/ModbusObserver.java`
- Create: `decode/src/main/java/dev/krillin/huginn/decode/ObservationResult.java`
- Test: `decode/src/test/java/dev/krillin/huginn/decode/ModbusObserverTest.java`

**요청/응답 판정 규칙 — 신호 둘을 모아 결합한다.**

한 대화는 4-tuple을 뒤집은 두 스트림이다(한쪽만 잡혔을 수도 있다). 둘 중 **클라이언트 방향만** `Observation`을 만든다.

| 신호 | 성립 조건 | 가리키는 방향 |
|---|---|---|
| **S1 · SYN** | 두 방향 중 `sawSynOnly`가 참인 방향이 **정확히 하나**다. **캡처에 없는 방향은 거짓으로 본다** | 그 방향이 클라이언트. SYN-without-ACK는 연결을 연 쪽만 보낸다. **SYN+ACK가 `sawSynOnly`가 아닌 것이 이 신호의 전부다** — `syn` 비트만 봤다면 핸드셰이크가 잡힌 모든 대화에서 양쪽 다 서고, 서버→클라이언트만 잡힌 캡처가 "SYN 있음"으로 들어와 응답을 요청으로 읽는다 |
| **S2 · PDU 형태** | 각 방향에 `ModbusShape.ofStream(그 방향의 프레임들)`을 돌린다. **캡처에 없는 방향은 프레임 0개이므로 `UNKNOWN`이다.** 아래 네 갈래로 갈린다 | — |
| | 한쪽만 `REQUEST_ONLY` | 그 방향이 클라이언트 |
| | 한쪽만 `RESPONSE_ONLY`(그리고 `REQUEST_ONLY`가 없다) | **반대 방향**이 클라이언트. 그 방향이 캡처에 없으면 R5로 간다 |
| | **양쪽이 같은 형태**(둘 다 `REQUEST_ONLY`이거나 둘 다 `RESPONSE_ONLY`) | **모순 — 즉시 판정 불가.** 한 대화에서 양쪽이 같은 역할일 수 없다. 한 4-tuple에 연결이 둘 묶였거나 재조립이 어긋난 것이다 |
| | 양쪽 다 `UNKNOWN` | 미성립 |

**결합 규칙:**

- **R1.** S2가 **모순**이면 판정 불가.
- **R2.** S1과 S2가 **모두 성립하는데 서로 다른 방향**을 가리키면 판정 불가.
- **R3.** 둘 중 하나라도 성립하면 그 방향을 쓴다(둘 다 성립하면 R2에 걸리지 않았으므로 같은 방향이다).
- **R4.** 둘 다 미성립이면 판정 불가.
- **R5.** R3이 고른 방향이 **캡처에 없으면**(응답만 잡힘) 판정 불가. 요청을 못 본 것이지 위반이 없는 것이 아니다.

R1~R4가 방향 선택을 남김없이 소진하고, R5는 R3의 선택에 걸리는 사후 가드다. 판정 불가는 전부 `UNDECIDABLE` 관찰 한 건을 남기고 **그 대화를 거기서 끝낸다.**

**왜 우선순위가 아니라 일치·불일치인가.** 앞선 개정은 S1을 S2보다 앞에 두었는데 **방어할 수 없다.** 조립기는 4-tuple만으로 스트림 키를 잡고 **연결 경계를 모른다** — ISN 추적도, FIN·RST 처리도, 시간 창도 없다(Task 8). 그래서 같은 4-tuple 위에 역할이 뒤바뀐 연결이 둘 있으면 한 대화로 합쳐지고, `sawSynOnly`는 **지금 해석 중인 프레임과 무관한 연결**에서 온다. "SYN-without-ACK는 연결을 연 쪽만 보낸다"는 참이지만, 그것이 확정하는 것은 *그 4-tuple 위 어떤 연결의* 개시자이지 *지금 읽는 바이트의* 방향이 아니다. S2는 해석 대상 프레임 자체에서 나오는 직접 증거다. **둘이 어긋나면 어느 쪽도 믿지 않는다.**

**R4·R5가 이 규칙의 핵심이다.** "먼저 보낸 쪽"만으로 판정하면 한 방향만 잡힌 캡처에서 그 방향이 자동으로 "먼저"가 된다. 서버→클라이언트만 잡힌 캡처(비대칭 SPAN, PLC를 출발지로 건 BPF 필터, 요청 이후에 시작된 캡처)에서 **응답을 요청으로 읽고, FC 16 응답이 `WRITE`가 되고, PLC가 미등록 출발지가 되어 HIGH 오탐**이 난다. 설계 §5-⑤의 "서버 쪽을 판정할 수 없는 스트림은 `UNDECIDABLE`"이 정확히 이 경우를 가리킨다.

### 포트로는 방향을 판정하지 않는다 — 개정 이력

포트 휴리스틱은 **거울상을 원리적으로 구별하지 못한다.** "낮은 쪽이 서버"라는 전제는 낮은 쪽이 정말 리스닝 포트일 때만 참인데, 프레임만 보고는 확인할 방법이 없다. 조건을 좁히면 구멍이 막히는 게 아니라 **경계 너머로 옮겨간다.** 세 번 반복한 뒤 신호를 없앴다.

| 개정 | 조건 | 뚫린 배치 |
|---|---|---|
| rev 4 | 두 포트가 다르면 낮은 쪽이 서버 | 서버 55000 / 클라 49500 → 49500을 서버로 |
| rev 5 | (a) 한쪽만 <1024 · (b) 한쪽만 <32768 | (b)의 거울상 — 클라 1288 / 서버 50502 → 1288을 서버로 |
| rev 6 | (a)만, 상대가 ≥32768일 때 | (a)의 거울상 — **클라 502(방화벽 통과용 바인드) / 서버 55000** → 502를 서버로 |

rev 6이 뚫린 자리가 결정적이다. 이 문서가 **각각 참이라고 선언한 두 사실**을 한 대화에 합치면 바로 나온다 — 클라이언트가 `502↔502`만 허용하는 방화벽을 지나려고 로컬 포트 502를 바인딩하는 관행(Moxa MGate 류 게이트웨이의 client 모드)과, 서버가 비표준 고포트에 있는 우회. 그러면 "정확히 한쪽만 1024 미만, 다른 쪽 32768 이상"이 성립하면서 **정확히 반대를 가리킨다.**

그리고 **포트 신호가 유일한 결정 근거가 되는 영역이 하필 가장 비싼 영역이다.** S2(형태)가 `UNKNOWN`인 대화는 대부분 **FC 5·6·22 에코만 오가는 대화**인데, 그 셋은 **전부 `WRITE`**다. 즉 포트가 틀리면 대가는 항상 HIGH다. 이득 영역이 없다.

**남는 손실:** SYN도 없고 에코 프레임만 오간 대화는 `UNDECIDABLE`이다. 표준 배치(`hmi:40000 → plc:502`)의 읽기·다중쓰기 폴링은 S2가 판정하므로 영향이 없다. 미검출은 리포트가 `UNDECIDABLE 대화`로 드러내므로 운영자가 조사한다.

**시각 신호도 쓰지 않는다.** rev 4에 `TcpStream.at`이 이른 쪽을 클라이언트로 보는 신호가 있었으나 뺐다. 필요한 상황은 정의상 SYN이 없는 캡처인데 그런 캡처는 대개 대화 중간부터 시작한다. 20ms 주기 폴링에 5ms 응답 지연이면 **첫 패킷이 응답일 확률이 약 25%**이고 그때 신호는 정확히 반대를 가리킨다. 판정할 수 없으면 `UNDECIDABLE`로 내는 것이 이 도구의 답이다(Task 9의 재동기화 거부와 같은 판단이다).

**한 대화가 한 TCP 연결이라는 보장은 없다.** 조립기가 연결 경계를 모르므로(위 참조) 포트 재사용·재접속이 있으면 여러 연결이 한 대화로 묶인다. S2의 모순 갈래가 그 경우를 잡아 `UNDECIDABLE`로 낸다. 2차에서 S7comm을 붙일 때 다시 시험받을 한계다.


**계수 단위는 대화다.** 리포트가 "대화"로 적으므로 세는 단위도 대화로 맞춘다. 한 대화는 다음 셋 중 **정확히 하나**다:

- **대상 외** — 그 대화의 어느 스트림에서도 유효 Modbus 프레임이 하나도 안 나왔다
- **해독** — 클라이언트 방향을 정했고 그 방향에서 프레임을 하나 이상 뽑아 관찰을 만들었다
- **UNDECIDABLE** — Modbus 대화이지만 **프레임에서** 관찰을 하나도 만들지 못했다(판정 불가, 또는 클라이언트 방향이 캡처에 없음). 이 대화도 `UNDECIDABLE` 관찰은 한 건 낸다

셋의 합이 전체 대화 수다. **해독한 대화에서도 `UNDECIDABLE` 관찰은 나올 수 있다**(잔여 바이트·갭·절단·FC 43). 그것은 대화가 아니라 **관찰** 단위로 세며 리포트에서 별도 줄로 낸다 — 두 수를 한 칸에 담으면 FC 43만 잔뜩 든 캡처가 "전부 해독함"으로 보인다.

- [ ] **Step 1: 실패하는 테스트 작성**

테스트 헬퍼 — `decode` 테스트 소스에 둔다. 청크 2의 `PcapBuilder`는 `pcap` 모듈 테스트 소스라 여기서 보이지 않으므로 `TcpStream`을 직접 만든다.

```java
/** Task 9 의 ModbusFixtures 를 그대로 쓴다 — mbap·pdu·concat 모두 public static 이다. */
private static TcpStream stream(String src, int sport, String dst, int dport, byte[] bytes,
                                Instant at, boolean sawSynOnly, boolean hasGap, boolean truncated) { ... }

/** 흔한 경우의 축약 — at 은 EPOCH, 플래그는 전부 false. */
private static TcpStream stream(String src, int sport, String dst, int dport, byte[] bytes) { ... }

private ObservationResult observe(TcpStream... streams) {
    return ModbusObserver.observe(List.of(streams));
}

// 이 파일이 쓰는 픽스처
private final TcpStream requestStream =                 // hmi:40000 → plc:502, FC 3 한 프레임
    stream("10.0.1.20", 40000, "10.0.2.11", 502, ModbusFixtures.mbap(1, 1, 3, ModbusFixtures.pdu(0, 2)));
private final TcpStream responseStream =                // plc:502 → hmi:40000, FC 3 응답
    stream("10.0.2.11", 502, "10.0.1.20", 40000, ModbusFixtures.mbap(1, 1, 3, new byte[]{4, 0, 0, 0, 0}));
private final TcpStream responseOnlyStream = responseStream;   // 짝이 없는 단독 스트림
private final TcpStream sshStream =
    stream("10.0.1.20", 40000, "10.0.3.5", 22, "SSH-2.0-OpenSSH_9.0\r\n".getBytes());
private final TcpStream truncatedSshStream = /* 같은 바이트, truncated = true */ ...;
```

```java
@Test
void 요청만_Observation이_된다() {
    // 요청 hmi→plc(FC 3)와 응답 plc→hmi(FC 3)가 모두 있는 대화.
    // 응답까지 관찰하면 출발지·목적지가 뒤집혀 정상 통신이 위반이 된다.
    ObservationResult r = observe(requestStream, responseStream);
    assertEquals(1, r.observations().size());
    assertEquals("10.0.1.20", r.observations().get(0).source().address());
}

@Test
void 관찰_시각은_스트림의_가장_이른_세그먼트_시각이다() { /* 입력 순서상 첫 번째가 아니다 — 청크 2 TcpStream.at */ }

@Test
void 한_스트림의_프레임_여러_개가_각각_관찰이_된다() { /* ... */ }

@Test
void Modbus가_아닌_스트림은_관찰도_미해독도_아니다() {
    // SSH 스트림 하나만 있는 캡처 → 관찰 0, UNDECIDABLE 0, 대상 외 1
    ObservationResult r = observe(sshStream);
    assertTrue(r.observations().isEmpty());
    assertEquals(0, r.decodedConversations());
    assertEquals(0, r.undecidableConversations());
    assertEquals(1, r.skippedConversations());
}

@Test
void 대화_수는_세_계수의_합과_같다() {
    // 응답 방향 스트림은 Modbus 이지만 관찰을 만들지 않는다. 어느 칸에도 안 세면
    // "해독한 대화 6" 이 6 인지 12 인지 알 수 없고 합이 맞지 않는다.
    ObservationResult r = observe(requestStream, responseStream, sshStream);
    assertEquals(2, r.decodedConversations() + r.undecidableConversations() + r.skippedConversations());
    assertEquals(1, r.decodedConversations());
    assertEquals(1, r.skippedConversations());
}

@Test
void Modbus_스트림_안의_미해독_바이트는_UNDECIDABLE_관찰을_만든다() { /* ... */ }

@Test
void 갭이_있는_스트림은_연속_구간만_해독하고_나머지는_UNDECIDABLE이다() { /* ... */ }

@Test
void 형태를_모르면_SYN이_결정한다() {
    // FC 6 은 응답이 요청의 에코라 양쪽 다 UNKNOWN → S2 미성립. S1 만 남는다.
    // 포트는 40000 → 502 를 가리키지만 SYN 은 502 쪽에 서 있다(포트 재사용·비표준 배치).
    // 포트를 보는 구현이 남아 있으면 여기서 갈린다.
    ObservationResult r = observe(
        stream("10.0.2.11", 502, "10.0.1.20", 40000, ModbusFixtures.mbap(1, 1, 6, ModbusFixtures.pdu(0, 42)),
               Instant.EPOCH, /* sawSynOnly */ true, false, false),
        stream("10.0.1.20", 40000, "10.0.2.11", 502, ModbusFixtures.mbap(1, 1, 6, ModbusFixtures.pdu(0, 42)),
               Instant.EPOCH, /* sawSynOnly */ false, false, false));
    assertEquals(1, r.observations().size());
    assertEquals("10.0.2.11", r.observations().get(0).source().address());
}

@Test
void SYN과_형태가_어긋나면_판정하지_않는다() {
    // 조립기는 4-tuple 만으로 키를 잡고 연결 경계를 모른다. 502↔502 게이트웨이 쌍에서
    // X 가 연 유휴 연결의 SYN 과, Y 가 연 다른 연결의 데이터가 한 대화로 묶인다.
    // SYN 은 X→Y 를, 형태는 Y→X 를 가리킨다 — 그리고 형태가 옳다.
    // 우선순위를 두면 어느 쪽을 앞에 놓든 한쪽 캡처에서 HIGH 오탐이 난다.
    ObservationResult r = observe(
        stream("10.0.1.30", 502, "10.0.2.11", 502,
               ModbusFixtures.mbap(7, 1, 16, new byte[]{0, 100, 0, 1}),        // RESPONSE_ONLY
               Instant.EPOCH, /* sawSynOnly */ true, false, false),
        stream("10.0.2.11", 502, "10.0.1.30", 502,
               ModbusFixtures.mbap(7, 1, 16, new byte[]{0, 100, 0, 1, 2, 0, 5}),  // REQUEST_ONLY
               Instant.EPOCH, /* sawSynOnly */ false, false, false));
    assertEquals(1, r.observations().size());
    assertEquals(Access.UNDECIDABLE, r.observations().get(0).access());
    assertEquals(1, r.undecidableConversations());
}

@Test
void SYN이_없으면_형태가_결정한다() {
    // 대화 중간부터 시작한 표준 배치. 요청 방향은 4바이트 FC 3(REQUEST_ONLY),
    // 응답 방향은 5바이트(RESPONSE_ONLY) — 포트를 보지 않고 갈린다.
    ObservationResult r = observe(requestStream, responseStream);
    assertEquals(1, r.observations().size());
    assertEquals("10.0.1.20", r.observations().get(0).source().address());
    assertEquals(Access.READ, r.observations().get(0).access());
}

@Test
void 양쪽이_같은_형태면_대화가_잘못_묶인_것이라_판정하지_않는다() {
    // 한 대화에서 양쪽이 모두 요청일 수 없다. 한 4-tuple 에 연결이 둘 묶였거나
    // 재조립이 어긋난 것이다. 다수결로 밀어붙이지 않는다.
    ObservationResult r = observe(
        stream("10.0.1.30", 502, "10.0.2.11", 502, ModbusFixtures.mbap(1, 1, 3, ModbusFixtures.pdu(0, 2))),
        stream("10.0.2.11", 502, "10.0.1.30", 502, ModbusFixtures.mbap(2, 1, 3, ModbusFixtures.pdu(0, 4))));
    assertEquals(1, r.observations().size());
    assertEquals(Access.UNDECIDABLE, r.observations().get(0).access());
    assertEquals(1, r.undecidableConversations());
}

@Test
void 한_방향만_잡힌_캡처는_요청으로_단정하지_않는다() {
    // 서버→클라이언트만 잡힌 캡처를 요청으로 읽으면 응답의 FC 16 이 WRITE 가 되고
    // PLC 가 미등록 출발지가 되어 HIGH 오탐이 난다. 이 청크 개정의 핵심 가드다.
    ObservationResult r = observe(responseOnlyStream);
    // allMatch 만 두면 관찰을 0건 내는 구현도 통과한다 — 크기를 먼저 못박는다.
    assertEquals(1, r.observations().size());
    assertEquals(Access.UNDECIDABLE, r.observations().get(0).access());
    assertEquals(1, r.undecidableConversations());
    assertEquals(0, r.decodedConversations());
}

@Test
void 양쪽_다_임시_포트면_판정_불가다() {
    // 비표준 고포트 우회 + 단방향 캡처. "낮은 포트가 서버" 만으로 두면 낮은 쪽이
    // 49500(클라이언트)이라 서버 방향이 클라이언트로 지목되고, FC 16 응답이 WRITE 가 되어
    // PLC 가 미등록 출발지로 HIGH 오탐이 난다. 하필 이 도구가 가장 잡아야 할 대상이다.
    ObservationResult r = observe(
        stream("10.0.2.11", 55000, "10.0.1.20", 49500,
               ModbusFixtures.mbap(1, 1, 16, new byte[]{0, 0, 0, 2})));   // FC 16 응답
    assertEquals(1, r.observations().size());
    assertEquals(Access.UNDECIDABLE, r.observations().get(0).access());
    assertEquals(1, r.undecidableConversations());
}

@Test
void 서버_포트가_더_높아도_형태로_판정한다() {
    // 거울상 가드 ①. 클라 1288(WinCE HMI 임시 포트) / 서버 50502.
    // "낮은 쪽이 서버" 계열 규칙은 1288 을 서버로 지목해 응답을 요청으로 읽고,
    // FC 16 응답이 WRITE 가 되어 PLC 가 미등록 출발지로 HIGH 오탐이 난다.
    // 양방향이 다 잡혀 있어 단방향 가드(R5)가 구제하지 못한다.
    // S2(형태)가 포트를 보지 않고 9바이트 요청 / 4바이트 응답으로 갈라 준다.
    ObservationResult r = observe(
        stream("10.0.1.20", 1288, "10.0.2.11", 50502,
               ModbusFixtures.mbap(1, 1, 16, new byte[]{0, 0, 0, 2, 4, 0, 1, 0, 2})),
        stream("10.0.2.11", 50502, "10.0.1.20", 1288,
               ModbusFixtures.mbap(1, 1, 16, new byte[]{0, 0, 0, 2})));
    assertEquals(1, r.observations().size());
    assertEquals("10.0.1.20", r.observations().get(0).source().address());
    assertEquals(Access.WRITE, r.observations().get(0).access());
    assertEquals(1, r.decodedConversations());
}

@Test
void 형태를_모르고_SYN도_없으면_판정_불가다() {
    // FC 6 에코만 오가고 핸드셰이크도 못 잡은 대화. 두 신호가 다 침묵한다.
    // **여기서 포트를 보면 안 된다** — 이 배치는 클라 502(방화벽 통과용 바인드) /
    // 서버 55000(비표준 포트 우회)이라 "낮은 쪽이 서버" 계열 규칙이 정확히 뒤집힌다.
    // 그리고 FC 5·6·22 는 전부 WRITE 라 틀리면 대가가 항상 HIGH 다.
    ObservationResult r = observe(
        stream("10.0.1.30", 502, "10.0.2.11", 55000,
               ModbusFixtures.mbap(1, 1, 6, ModbusFixtures.pdu(0, 42))),
        stream("10.0.2.11", 55000, "10.0.1.30", 502,
               ModbusFixtures.mbap(1, 1, 6, ModbusFixtures.pdu(0, 42))));
    assertEquals(1, r.observations().size());
    assertEquals(Access.UNDECIDABLE, r.observations().get(0).access());
    assertEquals(1, r.undecidableConversations());
    assertEquals(0, r.decodedConversations());
}

@Test
void 클라이언트가_특권_포트를_바인딩해도_형태로_판정한다() {
    // 502↔502 만 허용하는 방화벽을 지나려고 로컬 포트 502 를 바인딩한 클라이언트.
    // 포트를 보는 규칙은 502 를 서버로 단정해 40000→502 응답 방향을 클라이언트로 읽는다.
    // 형태는 그 방향이 응답임을 말한다 — 관례가 아니라 구조가 근거다.
    ObservationResult r = observe(
        stream("10.0.2.11", 40000, "10.0.1.30", 502,
               ModbusFixtures.mbap(1, 1, 16, new byte[]{0, 0, 0, 2})),          // 응답 형태
        stream("10.0.1.30", 502, "10.0.2.11", 40000,
               ModbusFixtures.mbap(1, 1, 16, new byte[]{0, 0, 0, 2, 4, 0, 1, 0, 2})));  // 요청 형태
    assertEquals(1, r.observations().size());
    assertEquals("10.0.1.30", r.observations().get(0).source().address());
    assertEquals(Access.WRITE, r.observations().get(0).access());
}

@Test
void 절단된_비Modbus_스트림은_대상_외가_이긴다() {
    // tcpdump -s 96 환경에서는 SSH 스트림도 전부 절단이다.
    // 절단이 이기면 커버리지 지표가 다시 비산업 트래픽에 지배된다.
    ObservationResult r = observe(truncatedSshStream);
    assertEquals(0, r.undecidableConversations());
    assertEquals(1, r.skippedConversations());
}

@Test
void 판정_불가_대화는_UNDECIDABLE_관찰을_한_건만_남긴다() {
    // 판정 불가이면서 절단이기도 한 스트림 — 단방향 캡처는 보통 SPAN·snaplen 산물이라
    // 이 조합이 오히려 흔하다. 판정 불가에서 끝내지 않으면 잔여·절단 처리가 한 번 더 돌아
    // 관찰 두 건, undecidableConversations 도 2 가 된다.
    ObservationResult r = observe(/* responseOnlyStream 과 같되 truncated = true */);
    assertEquals(1, r.observations().size());
    assertEquals(1, r.undecidableConversations());
}

@Test
void 해독한_대화의_절단은_UNDECIDABLE_관찰을_함께_남긴다() {
    // 프레임은 뽑혔지만 뒤가 잘렸다. 관찰은 나오되 "다 봤다" 고 말하면 안 된다.
    // 단계 6-① 의 이중 계수 금지를 고정하는 유일한 테스트다.
    ObservationResult r = observe(
        stream("10.0.1.20", 40000, "10.0.2.11", 502, ModbusFixtures.mbap(1, 1, 3, ModbusFixtures.pdu(0, 2)),
               Instant.EPOCH, false, false, /* truncated */ true),
        responseStream);
    assertEquals(2, r.observations().size(), "프레임 관찰 1 + 절단 관찰 1");
    assertEquals(1, r.decodedConversations());
    assertEquals(0, r.undecidableConversations(), "대화는 '해독' 이다 — 관찰 단위와 섞지 않는다");
}

@Test
void 클라이언트_방향만_프레임을_못_뽑은_대화도_어딘가에_센다() {
    // 클라이언트 스트림이 프레임 중간에서 시작해 재동기화를 하지 않으므로 프레임 0개,
    // 서버 스트림은 마침 경계에서 시작해 정상. 서버 방향만 RESPONSE_ONLY 라 S2 가 성립해
    // 반대 방향을 지목하고, 그 방향도 캡처에 있으니 R5 가 발동하지 않는다.
    // 여기서 종결 규칙이 없으면 이 대화가 세 계수 어디에도 안 세여
    // 완료 조건의 "합 == 전체 대화 수" 가 깨진다.
    ObservationResult r = observe(
        stream("10.0.1.20", 40000, "10.0.2.11", 502, "쓰레기 바이트".getBytes(StandardCharsets.UTF_8)),
        stream("10.0.2.11", 502, "10.0.1.20", 40000, ModbusFixtures.mbap(1, 1, 3, new byte[]{4, 0, 0, 0, 0})));
    assertEquals(0, r.decodedConversations());
    assertEquals(1, r.undecidableConversations());
    assertEquals(1, r.decodedConversations() + r.undecidableConversations() + r.skippedConversations());
}
```

- [ ] **Step 2: 실패 확인**

Run: `mvn -pl decode -am test`
Expected: 컴파일 실패 — `ModbusObserver`·`ObservationResult` 심볼 없음

- [ ] **Step 3: 구현**

```java
/**
 * 계수 단위는 **대화**다(리포트가 "대화"로 적는다). 셋은 배타적이며 합이 전체 대화 수다.
 *
 * @param decodedConversations     클라이언트 방향을 정했고 그 방향에서 관찰을 하나 이상 만든 대화 수
 * @param undecidableConversations Modbus 대화이지만 관찰을 하나도 만들지 못한 수
 *                                 (판정 불가, 또는 클라이언트 방향이 캡처에 없음)
 * @param skippedConversations     어느 스트림에서도 유효 프레임이 안 나온 대화 수
 *
 * 해독한 대화에서 나오는 UNDECIDABLE 관찰(잔여 바이트·갭·절단·FC 43)은 여기 세지 않는다 —
 * 그것은 관찰 단위이며 Reconciler.undecidableCount 가 센다. 두 수는 다르며 리포트가 따로 낸다.
 */
public record ObservationResult(List<Observation> observations,
    int decodedConversations, int undecidableConversations, int skippedConversations) {}
```

`ModbusObserver`는 **`public final class`**, `observe`는 **`public static`**이다 — 청크 3의 `Pipeline`이 부른다. `ModbusFramer`·`ModbusAccess`·`ModbusObjectRef`는 `decode` 안에서만 쓰이므로 패키지-프라이빗으로 충분하다. `ModbusFrame`·`FramingResult`는 Task 9 가 `public record` 로 선언한다 — `decode` 밖 소비자는 없지만 레코드는 계약이므로 일관되게 둔다.

진입점: `ModbusObserver.observe(List<TcpStream> streams) → ObservationResult`.

1. 각 스트림에 `ModbusFramer.frames(stream.contiguousPrefix())`를 돌린다
2. 스트림을 **4-tuple을 뒤집어 짝지어 대화로 묶는다**. 키는 두 (주소, 포트) 쌍을 **주소 문자열 오름차순, 같으면 포트 오름차순**으로 정렬한 것이라 방향에 무관하다. 포트가 다르면 다른 키이므로 같은 호스트 쌍의 연결 둘은 합쳐지지 않는다. 짝이 없으면 단방향 대화다. **대화의 순회 순서는 각 대화가 입력 `List<TcpStream>`에 처음 등장한 순서다** — 결정성은 완료 조건이므로 여기서 못박는다
3. 대화의 **어느 스트림에서도** `isModbusStream == true`가 아니면 **절단·갭 여부와 무관하게** `skippedConversations`를 올리고 그 대화를 끝낸다(우선순위 표)
4. 신호 표와 결합 규칙으로 클라이언트 방향을 고른다(S2는 각 방향의 프레임 목록에 `ModbusShape.ofStream`을 돌려 얻는다). **R1·R2·R4(판정 불가)이거나 R5(고른 방향이 캡처에 없음)이면** `Access.UNDECIDABLE` 관찰 **한 건**을 만들고 `undecidableConversations`를 올린 뒤 **그 대화를 여기서 끝낸다.** 끝내지 않으면 6이 이어 돌아 같은 대화에서 관찰 두 건과 이중 계수가 난다 — 단방향 캡처는 대개 SPAN·snaplen 산물이라 절단을 함께 달고 있어 흔한 경우다.
   이 관찰의 `source`/`target`·`at`은 **그 대화에 잡힌 스트림 중 입력 목록에 먼저 등장한 쪽**의 것을 쓴다(`objectRef`는 `"-"`). R4는 스트림이 둘일 수 있으므로 "잡힌 스트림"만으로는 결정되지 않는다 — 어느 쪽을 쓸지 정하지 않으면 리포트에 찍히는 주소가 구현자 재량이 된다
5. 클라이언트 방향의 각 프레임을 `Observation`으로 만든다 — `at`은 `TcpStream.at`, `source`/`target`은 그 스트림의 4-tuple, `protocol`은 `Protocol.MODBUS_TCP`, `access`는 `ModbusAccess.of(fc)`, `objectRef`는 `ModbusObjectRef.of(fc, pdu)`
6. **종결.** 5에서 프레임으로 만든 관찰이
   - **하나 이상이면** `decodedConversations`를 올린다. 이어서 클라이언트 방향에 `undecodedBytes > 0`이거나 `hasGap`이거나 `truncated`면 `UNDECIDABLE` 관찰을 **한 건 더** 붙인다(`objectRef`는 `"-"`). **대화 계수는 더 건드리지 않는다** — 이 대화는 이미 '해독'이다
   - **0건이면** `UNDECIDABLE` 관찰 한 건을 만들고 `undecidableConversations`를 올린다. 이 관찰의 `source`/`target`/`at`은 **고른 클라이언트 방향 스트림**의 것을 쓴다(`objectRef`는 `"-"`). **이 갈래가 없으면 대화가 세 계수 어디에도 안 세인다** — 클라이언트 스트림이 프레임 중간에서 시작해 `isModbusStream == false`인데 서버 스트림은 정상인 대화가 그렇다. 3은 "어느 스트림에서도"라 안 걸리고, S2는 성립하며 지목한 방향도 캡처에 있어 4도 안 걸린다. `tcpdump -s 96`으로 폴링 중간부터 뜬 캡처에서 흔하다

- [ ] **Step 4: 통과 확인**

Run: `mvn -pl decode -am test`
Expected: `decode` 모듈 `Tests run: 81, Failures: 0` (61 + `ModbusObserverTest` 20)

- [ ] **Step 5: 커밋**

```bash
git add decode/src
git commit -m "feat: 요청만 관찰한다 — 응답을 관찰하면 정상 통신이 전부 위반이 된다"
```

---

### Task 14: 파이프라인과 CLI

**Files:**
- Create: `cli/src/main/java/dev/krillin/huginn/cli/Pipeline.java`
- Create: `cli/src/main/java/dev/krillin/huginn/cli/Report.java`
- Create: `cli/src/main/java/dev/krillin/huginn/cli/Huginn.java`
- Modify: `cli/pom.xml` — shade 플러그인, 그리고 `pcap`·`decode` test-jar 의존
- Modify: `pcap/pom.xml`, `decode/pom.xml` — `maven-jar-plugin`의 `test-jar` 골 추가
- Test: `cli/src/test/java/dev/krillin/huginn/cli/EndToEndTest.java`

**이 태스크의 테스트는 전부 실제 pcap 바이트를 필요로 하는데, `PcapBuilder`는 `pcap` 모듈의 테스트 소스에 있다.** 대책 없이 두면 Step 3 에서 구현자가 pcap 조립기를 다시 쓰게 되고 두 벌이 갈라진다. `pcap/pom.xml`에 `test-jar` 골을 붙이고 `cli/pom.xml`에 test 스코프로 당겨 쓴다(`PcapBuilder`는 Task 6 에서 이미 `public`이다).

```xml
<!-- pcap/pom.xml -->
<plugin>
  <groupId>org.apache.maven.plugins</groupId>
  <artifactId>maven-jar-plugin</artifactId>
  <executions><execution><goals><goal>test-jar</goal></goals></execution></executions>
</plugin>
```
```xml
<!-- cli/pom.xml -->
<dependency>
  <groupId>dev.krillin.huginn</groupId><artifactId>huginn-pcap</artifactId>
  <version>${project.version}</version><classifier>tests</classifier><scope>test</scope>
</dependency>
```

**`decode`에도 같은 배선이 필요하다.** 위 테스트들은 MBAP 바이트도 필요한데 `ModbusFixtures`는 `decode` 테스트 소스에 있다. 그대로 두면 구현자가 `cli` 테스트에 MBAP 조립기를 다시 짜게 되어 "두 벌이 갈라진다"는 이 문단의 우려가 그대로 재현되고, 손으로 짠 그 헬퍼가 완료 조건의 grep 에 걸린다. `decode/pom.xml`에도 `test-jar` 골을 붙인다(`ModbusFixtures`는 Task 9 에서 이미 `public`이다).

`maven-jar-plugin` 버전은 Task 1 이 이미 부모 POM 에 고정해 두었다 — 확인만 한다. 파일 구조 표의 `cli` 행에도 이미 반영돼 있다.

세 층으로 나눈다 — `main`이 `System.exit`을 부르면 테스트에서 JVM 이 죽는다.

```java
public static void main(String[] args) { System.exit(run(args)); }
public static int run(String[] args)      // 인자 검증 · 파일 읽기 · 예외 → 종료 코드. 테스트는 이것을 부른다
Report Pipeline.run(byte[] pcap, String policyYaml)  // 순수 실행
```

`PcapException`·`PolicyException`은 `Huginn.run`이 잡아 **2**로 매핑한다.

**종료 코드:** 0 = 위반 없음, 1 = 위반 있음, 2 = 사용법·입력·계약 오류. **`UNDECIDABLE`이 많아도 위반이 0이면 0을 낸다** — 커버리지는 리포트가 항상 내므로 종료 코드까지 흐리지 않는다.

**리포트 형식:**

각 줄이 어느 값인지 못박는다 — **`UNDECIDABLE`은 두 개의 서로 다른 수**이므로 이름만으로는 구별되지 않는다.

| 줄 | 출처 |
|---|---|
| 처리 패킷 | `PcapReader`가 읽은 패킷 수 |
| 대상 외 패킷 | `DecodedFrames.skipped` |
| 해독한 대화 | `ObservationResult.decodedConversations` |
| 대상 외 대화 | `ObservationResult.skippedConversations` |
| UNDECIDABLE 대화 | `ObservationResult.undecidableConversations` — 관찰을 하나도 못 만든 대화 |
| UNDECIDABLE 관찰 | `ReconcileResult.undecidableCount` — **모든** UNDECIDABLE 관찰 수. 판정 불가 대화가 남긴 1건 + 해독한 대화의 잔여·갭·절단·FC 43. 판정 불가 대화는 각각 정확히 1건을 기여하므로 `UNDECIDABLE 관찰 ≥ UNDECIDABLE 대화`이고, 차이는 해독한 대화가 낸 관찰 수다. 서로 다른 값이므로 둘 다 낸다 |

관찰 쪽을 빼면 FC 43만 잔뜩 든 캡처가 "대화 전부 해독"으로 보인다. 대화 쪽을 빼면 한 방향만 잡힌 캡처가 드러나지 않는다. 둘 다 필요하다.

```
Huginn — 통신 대사 결과
  처리 패킷        1,284
  대상 외 패킷        112
  해독한 대화           6
  대상 외 대화          3
  UNDECIDABLE 대화     1
  UNDECIDABLE 관찰     4

위반 2건
  [HIGH]   10.0.9.99:40000 → 10.0.2.11:502  MODBUS_TCP WRITE  holding:40001
           선언되지 않은 통신: 10.0.9.99:40000 → 10.0.2.11:502 MODBUS_TCP WRITE
  [MEDIUM] 10.0.9.99:40000 → 10.0.2.11:502  MODBUS_TCP READ   holding:40001
           선언되지 않은 통신: 10.0.9.99:40000 → 10.0.2.11:502 MODBUS_TCP READ
```

- [ ] **Step 1: 실패하는 테스트 작성**

```java
@Test
void 선언된_통신만_있는_캡처는_위반이_없다() {
    // 요청과 응답을 모두 넣는다 — 응답을 빼면 요청/응답 결함을 은폐하는 테스트가 된다.
}

@Test
void 미등록_장비의_쓰기를_잡는다() {
    // 깨뜨렸을 때 잡히는지가 본 검증이다. 정상 입력에서 0건인 것만으로는 증명되지 않는다.
}

@Test
void 비표준_포트의_우회를_잡는다() {
    // 502 가 아닌 포트로 같은 통신. 서버 50502 / 클라 1288 처럼 포트 신호(S2)가
    // 미성립이거나 거울상인 조합을 쓴다 — 우연히 S2 가 맞는 조합(8502/40000)을 고르면
    // PDU 형태 신호(S2)가 실제로 일하는지 시험하지 못한다.
}

@Test
void 포트가_502여도_프레이밍이_아니면_Modbus로_치지_않는다() { /* §5-① 을 양방향으로 고정 */ }

@Test
void 리포트는_커버리지를_함께_낸다() {
    Report r = Pipeline.run(capture, policy);
    String out = r.render();
    assertTrue(out.contains("처리 패킷"));
    assertTrue(out.contains("대상 외 패킷"));
    assertTrue(out.contains("해독한 대화"));
    assertTrue(out.contains("대상 외 대화"));
    assertTrue(out.contains("UNDECIDABLE 대화"));
    assertTrue(out.contains("UNDECIDABLE 관찰"), "대화 수와 관찰 수는 다른 값이며 둘 다 내야 한다");
}

@Test
void 비산업_트래픽은_UNDECIDABLE이_아니라_대상_외로_센다() {
    // 이 구분이 없으면 커버리지 지표가 캡처의 SSH·HTTP 양에 지배된다.
}

@Test
void 계약이_잘못되면_종료코드_2다() { /* 위반 1 과 구별된다 */ }

@Test
void 위반이_없으면_종료코드_0이다() {
    // 완료 조건의 "0/1/2 계약" 이 자동으로 지켜지게 한다.
    // Task 15 의 수동 실행에만 맡기면 회귀를 잡지 못한다.
}

@Test
void 위반이_있으면_종료코드_1이다() { /* UNDECIDABLE 이 많아도 위반이 0이면 0이다 */ }

@Test
void 같은_입력에_같은_리포트가_나온다() { /* 문자열 동일 */ }
```

- [ ] **Step 2: 실패 확인**

Run: `mvn -pl cli -am test`
Expected: 컴파일 실패

- [ ] **Step 3: 구현**

리포트의 천 단위 구분자는 `String.format(Locale.ROOT, "%,d", n)`로 낸다 — 기본 로케일에 맡기면 환경마다 문자열이 달라져 `같은_입력에_같은_리포트가_나온다`가 환경을 탄다.

`Pipeline`·`Report`는 패키지-프라이빗으로 충분하다 — `Huginn`과 `EndToEndTest`가 같은 패키지다.

`Pipeline.run`이 커버리지를 직접 집계한다 — `PcapReader`(처리 패킷 수), `FrameDecoder`(대상 외 패킷), `ModbusObserver`(해독·대상 외·UNDECIDABLE **대화**), `Reconciler`(위반, UNDECIDABLE **관찰**). `ReconcileResult`에는 패킷 수를 담을 자리가 없으므로 `Report`가 둘을 합쳐 든다.

`cli/pom.xml`에 shade 플러그인을 붙여 `huginn.jar` 하나로 실행되게 한다. `mainClass`는 `dev.krillin.huginn.cli.Huginn`이고, **`<finalName>huginn</finalName>`을 반드시 함께 준다** — 없으면 산출물이 `huginn-cli-0.1.0-SNAPSHOT.jar`가 되어 Task 15의 `java -jar cli/target/huginn.jar`가 바로 실패하고, 그 태스크가 닫으려던 §10 반증 시험이 또 안 돌아간다.

- [ ] **Step 4: 통과 확인**

Run: `mvn test`
Expected: 전체 `BUILD SUCCESS`, `cli` 모듈 `Tests run: 10, Failures: 0`

- [ ] **Step 5: 커밋**

```bash
git add cli/src cli/pom.xml
git commit -m "feat: 파이프라인과 CLI — 리포트는 커버리지를 함께 낸다"
```

---

## Chunk 4: 검증과 문서

코드 산출물이 없는 두 태스크다. 청크 3에서 끊어도 의존이 깨지지 않으므로 따로 둔다 — 청크 3이 1000줄 가이드라인을 넘었다.

### Task 15: 공개 캡처로 반증 조건을 실제로 시험한다

**Files:**
- Create: `scripts/fetch-samples.sh`, `scripts/fetch-samples.ps1`
- Create: `samples/README.md`
- Create: `samples/.gitignore` — 내려받은 캡처는 커밋하지 않는다
- Create: `samples/<capture>-policy.yaml` — 캡처별 정책(재현 가능한 부분이라 커밋한다)
- Modify: `docs/superpowers/specs/2026-09-05-huginn-design.md` — §10 판정 결과

설계 §10의 첫 반증 조건은 *"공개 ICS 캡처에서 `UNDECIDABLE` 비율이 압도적이면 Modbus 단독으로 유의미한 판정이 된다는 전제가 틀린 것"*이다. **내려받기만 하고 실행하지 않으면 이 조건은 한 번도 시험되지 않는다.**

- [ ] **Step 1: 내려받기 스크립트 작성**

출처와 SHA-256을 스크립트에 명시한다(4SICS ICS Lab, Netresec 공개 캡처 등). 주 개발 환경이 Windows이므로 `.ps1`을 함께 둔다. 캡처는 **저장소에 넣지 않는다**(라이선스가 제각각).

`samples/.gitignore`는 **캡처만 무시하고 정책 파일은 남긴다** — Step 4가 `git add samples`를 하는데 Step 2에서 만든 캡처별 정책이 재현 가능한 부분이다.

```gitignore
# 캡처는 라이선스가 제각각이라 커밋하지 않는다.
# 정책 파일(*-policy.yaml)은 재현 가능한 부분이라 커밋한다 — 아래 패턴에 걸리지 않는다.
*.pcap
*.pcapng
```

**`editcap`(Wireshark)이 이 프로젝트의 유일한 외부 도구다.** 윈도에서 PATH 에 없을 확률이 높으므로 스크립트가 먼저 존재를 확인하고, 없으면 설치 안내를 찍고 멈춘다 — 조용히 건너뛰면 캡처가 없는데도 성공한 것처럼 보인다.

**pcapng는 `PcapReader`가 거부한다.** 받은 파일이 pcapng이면 스크립트가 `editcap -F pcap`으로 정규화한다 — 그러지 않으면 캡처를 한 건도 못 읽어 반증 조건이 또 시험되지 않는다.

Run: `bash scripts/fetch-samples.sh` (또는 `pwsh scripts/fetch-samples.ps1`)
Expected: `samples/` 아래에 `.pcap` 파일들이 생기고 해시 검증이 전부 통과

- [ ] **Step 2: 실행하고 결과를 기록**

내려받은 각 캡처에 Huginn을 돌려 커버리지 여섯 수치를 `samples/README.md`에 표로 기록한다. 정책 파일은 캡처에서 관찰된 통신 중 일부만 선언해 위반이 나오는 형태로 만든다.

Run: `mvn -DskipTests package && java -jar cli/target/huginn.jar samples/<capture>.pcap samples/<capture>-policy.yaml`
Expected: 리포트가 출력되고 종료 코드가 0 또는 1(2가 나오면 입력·계약 문제이므로 먼저 해결한다)

- [ ] **Step 3: 반증 조건 판정**

`UNDECIDABLE` 비율이 높으면 원인을 적는다 — 프로토콜 선택이 틀렸는가, 요청/응답 판정이 R1·R2·R4(형태 모순·신호 불일치·둘 다 침묵)나 R5(단방향 캡처)로 빠졌는가, 캡처가 대화 중간부터 시작하는가. **판정 결과를 설계 문서 §10에 반영한다.**

Run: `git diff --stat docs/superpowers/specs/2026-09-05-huginn-design.md`
Expected: §10이 실제로 갱신되어 diff 에 나타나고, `samples/README.md`에 캡처별 여섯 수치와 판정 한 줄이 기록되어 있다

- [ ] **Step 4: 커밋**

```bash
git add scripts samples docs/superpowers/specs
git commit -m "test: 공개 ICS 캡처로 반증 조건을 시험한다"
```

---

### Task 16: README와 예시

**Files:**
- Create: `README.md`
- Create: `examples/policy.yaml`
- Create: `LICENSE` — Bifrost에서 복사(Apache-2.0)
- Test: `cli/src/test/java/dev/krillin/huginn/cli/ExamplePolicyTest.java`

- [ ] **Step 1: LICENSE 복사**

```bash
test -f ../bifrost/LICENSE && cp ../bifrost/LICENSE LICENSE
```

형제 저장소가 없으면 Apache-2.0 전문을 직접 받는다.

Run: `head -1 LICENSE`
Expected: `                                 Apache License` (줄 수는 출처마다 201/202로 갈리므로 기준으로 쓰지 않는다)

- [ ] **Step 2: 예시 정책 작성**

`examples/policy.yaml` — 설계 §4의 예시를 그대로 두되 **로딩에 성공하는 형태**여야 한다(모든 `from`/`to`가 `peers`에 선언되어 있을 것).

**예시가 썩지 않도록 테스트로 고정한다.** `cli/src/test/.../ExamplePolicyTest.java`에 저장소의 `examples/policy.yaml`을 읽어 `PolicyLoader.parse`가 성공하는지 확인하는 테스트 한 건을 둔다.

Run: `mvn -pl cli -am test`
Expected: `cli` 모듈 `Tests run: 11, Failures: 0`. **`-am`이 빠지면** `cli`가 의존하는 네 형제 SNAPSHOT을 못 찾아 테스트가 아니라 의존성 해석에서 실패한다(어느 태스크도 `mvn install`을 하지 않는다).

- [ ] **Step 3: README 작성**

Bifrost README의 톤을 따른다 — 무엇을 관찰하는지, **무엇을 하지 않는지**, 그리고 모든 주장에 대응하는 테스트가 무엇인지.

핵심 문장: *"fail-closed는 길목을 지나는 것만 막는다. Huginn은 지나지 않은 것을 본다."*

"하지 않는 것"에 다음을 명시한다 — 라이브 캡처, 능동 스캔, OPC UA·Sparkplug, 자동 차단, 절대 성능 주장, **게이트웨이 뒤 유닛ID 단위 판정**(정책이 IP 기준이라 게이트웨이 경유 우회는 보이지 않는다).

Run: `grep -c "하지 않는" README.md && head -1 README.md`
Expected: "하지 않는 것" 절이 존재하고, 첫 줄이 `# Huginn`

- [ ] **Step 4: 커밋**

```bash
git add README.md LICENSE examples cli/src
git commit -m "docs: README와 예시 정책"
```

---

## 완료 조건

- [ ] `mvn test` 전체 통과
- [ ] **`decode` 밖 어디에도 MBAP·PDU·함수코드·PDU 형태를 다루는 코드가 없다** (`Protocol.MODBUS_TCP`라는 *이름*은 정책 계약이 쓰므로 `reconcile`·`contract`에 있는 것이 정상이다)
      Run: `grep -rn "MBAP\|functionCode\|unitId\|protocolId\|ModbusShape\|REQUEST_ONLY" --include=*.java pcap/src/main contract/src/main reconcile/src/main cli/src/main` → Expected: 히트 0건 (테스트 소스는 제외한다 — 주장은 main 코드에 대한 것이고, `cli` 테스트는 `ModbusFixtures`를 정당하게 쓴다)
- [ ] `pcap`·`decode`·`reconcile` 모듈에 런타임 서드파티 의존이 없다
      Run: `mvn -pl pcap,decode,reconcile dependency:tree` → Expected: `compile`/`runtime` 스코프에 `com.fasterxml.*`가 없다
- [ ] **같은 pcap·정책을 두 번 돌리면 같은 리포트 문자열이 나온다** (Task 14 `같은_입력에_같은_리포트가_나온다`) — 결정성은 설계 §8의 시험 전략이자 스트림 열거·대화 순회 규칙의 존재 이유다
- [ ] 리포트가 커버리지 여섯 수치(처리 패킷·대상 외 패킷·해독한 대화·대상 외 대화·`UNDECIDABLE` 대화·`UNDECIDABLE` 관찰)를 항상 낸다
- [ ] **대화 계수 셋의 합이 전체 대화 수와 같다** — 어느 대화도 어느 칸에도 안 세이거나 두 번 세이지 않는다
- [ ] 위반이 든 합성 캡처에서 실제로 잡힌다 — 정상 캡처에서 0건인 것만으로는 증명되지 않는다
- [ ] **요청과 응답이 모두 든 정상 캡처에서 위반이 0건이다** — 요청/응답 결함의 회귀 가드
- [ ] **한 방향만 잡힌 캡처가 위반이 아니라 `UNDECIDABLE`로 나온다** — 클라이언트 판정의 회귀 가드
- [ ] **서버 포트가 클라이언트 포트보다 크거나, 클라이언트가 특권 포트를 바인딩한 양방향 캡처에서 방향이 올바로 판정된다** — PDU 형태(S2)가 포트를 보지 않고 갈라 준다. 위 단방향 가드로는 잡히지 않는다(둘 다 양방향이다)
- [ ] **방향 판정에 포트를 쓰는 코드가 없다** — 세 번 시도해 세 번 거울상에 뚫렸다. `sourcePort`·`targetPort`는 `Observation`을 만들 때 기록용으로만 쓴다
- [ ] **SYN과 PDU 형태가 어긋나면 위반이 아니라 `UNDECIDABLE`이다** — 조립기가 연결 경계를 모르므로 불일치는 "한 4-tuple에 연결이 둘"이라는 신호다
- [ ] **양쪽 방향이 같은 형태로 나오는 대화는 `UNDECIDABLE`이다** — 다수결로 밀어붙이지 않는다
- [ ] **SYN+ACK를 SYN으로 읽지 않는다** — 그러면 서버가 클라이언트로 판정되어 같은 오탐이 다른 경로로 되살아난다
- [ ] `java -jar cli/target/huginn.jar <capture> <policy>`가 실제로 실행되고 종료 코드가 0/1/2 계약을 지킨다
- [ ] 공개 ICS 캡처로 설계 §10의 반증 조건을 실제로 시험하고 결과를 기록했다
