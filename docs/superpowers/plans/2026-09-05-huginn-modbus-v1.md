# Huginn 1차 (Modbus/TCP) 구현 계획

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** pcap 파일에서 Modbus/TCP 요청을 해독해 선언된 `CommunicationPolicy`와 대조하고, 미등록 통신을 근거와 함께 보고하는 CLI를 만든다.

**Architecture:** 이음매(`Observation`)를 먼저 고정하고 아래로 내려간다. 순수 대사 로직 → pcap 읽기 → Modbus 해독 순. `decode` 밖은 프레이밍·함수코드를 모르며, 그 경계는 2차에 S7comm을 붙일 때 시험받는다. pcap·프로토콜 파싱은 외부 의존 없이 직접 구현해 테스트가 환경을 타지 않게 한다.

**Tech Stack:** Java 17 · Maven 멀티모듈 · JUnit 5.10.3 · Jackson(`contract` 모듈 한정) · 그 외 런타임 의존 없음

**설계 문서:** `docs/superpowers/specs/2026-09-05-huginn-design.md`

**저장소 상태:** git 초기화 완료, `.gitignore`(`target/` 포함) 있음, 설계·계획 문서가 커밋되어 있다. 코드는 아직 0줄.

---

## 파일 구조

| 모듈 | artifactId | 책임 | 서드파티 | 모듈 간 |
|---|---|---|---|
| `contract/` | `huginn-contract` | `CommunicationPolicy` 로딩·검증 | Jackson(YAML) | `huginn-reconcile` |
| `reconcile/` | `huginn-reconcile` | `Observation` 이음매, 대사, `Finding` | **없음** | 없음 |
| `pcap/` | `huginn-pcap` | pcap 파일 → 패킷 → TCP 스트림 | **없음** | 없음 |
| `decode/` | `huginn-decode` | MBAP 프레이밍·함수코드 → `Observation` | **없음** | `huginn-reconcile` · `huginn-pcap` |
| `cli/` | `huginn-cli` | 배선·리포트 | **없음** | 위 전부 |

**"외부 의존 없음"은 서드파티 라이브러리를 말한다.** 모듈 간 의존은 위 표대로 있다.

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
 * @param at        요청 프레임이 실린 첫 세그먼트의 캡처 시각
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
}
```

- [ ] **Step 2: 실패 확인**

Run: `mvn -pl contract -am test`
Expected: 컴파일 실패

- [ ] **Step 3: 구현**

`PolicyException extends RuntimeException`.

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

`PolicyLoader.parse(String yaml)`:

1. `new ObjectMapper(new YAMLFactory())` — `FAIL_ON_UNKNOWN_PROPERTIES`는 기본이 켜짐이므로 **끄지 않는다.**
2. **Jackson이 던지는 모든 예외(`JacksonException`)를 `PolicyException`으로 감싼다.** 감싸지 않으면 `알_수_없는_필드`·`깨진_YAML` 테스트가 `UnrecognizedPropertyException`/`JsonParseException`을 받아 실패한다.
3. 검증 — `version != 1`, `peers`/`allowed` null, peer id 중복, peer address 중복, `allowed`의 `from`/`to`가 미선언 id. **실패 메시지에 문제된 id나 주소를 포함한다.**
4. 주소→id 역인덱스와 `(fromAddress, toAddress, protocol) → Set<Access>` 조회표를 만들어 `CommunicationPolicy`를 반환한다.

`CommunicationPolicy`는 **`public boolean allows(String, String, Protocol, Access)` 하나만 노출**한다. `Access.UNDECIDABLE`이 들어오면 **조회 전에 false**를 반환한다.

**여기서 `PolicyView`를 참조하지 않는다.** 그 인터페이스는 Task 4에서 만들어지고 Task 5에서 붙인다 — 지금 참조하면 심볼이 없어 컴파일이 깨지고, 미리 만들면 Task 5의 RED가 사라진다. `allows`를 **public**으로 두는 것이 나중에 인터페이스를 붙일 때 시그니처가 그대로 맞는 조건이다.

- [ ] **Step 4: 통과 확인**

Run: `mvn -pl contract -am test`
Expected: `contract` 모듈 `Tests run: 10, Failures: 0`. (`-am` 때문에 `reconcile`의 1건도 함께 돌아 리액터 총합은 11이다.)

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
Expected: 컴파일 실패

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

`ReconcileResult`: `record ReconcileResult(List<Finding> findings, int observedCount, int undecidableCount)`. **`observedCount`는 입력 `Observation` 총수이며 `UNDECIDABLE`을 포함한다.**

`Reconciler.reconcile(List<Observation>)`은 입력 순서를 유지하며 한 번 훑는다.
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
Expected: 전체 `BUILD SUCCESS`, `contract` 11건 + `reconcile` 9건

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
| base seq | 그 방향에서 관찰된 **최소 seq** | 캡처가 대화 중간부터 시작하면 첫 seq는 임의값이다 |
| 겹치는 재전송 | **먼저 온 바이트가 이긴다**(first-wins) | 나중 세그먼트로 앞 내용을 덮어쓸 수 있으면 재전송 위장으로 판정을 속일 수 있다 |
| seq 랩어라운드 | **다루지 않는다** | 32비트를 `& 0xFFFFFFFFL`로 읽어 음수화만 막는다. 랩된 스트림은 갭으로 보고 UNDECIDABLE이 된다 |
| 스트림 열거 순서 | `LinkedHashMap` — 최초 등장 순서 | `HashMap`이면 리포트가 비결정적이 된다 |
| SYN 관찰 | 바이트는 버리되 **`sawSyn` 플래그는 기록** | 길이 0 세그먼트를 통째로 버리면 **클라이언트를 확정할 유일한 신호**까지 사라진다. 청크 3의 요청/응답 판정이 이 값에 기댄다 |
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

/** 테스트용 pcap 조립기. 외부 캡처 파일 없이 결정적으로 검증하기 위한 것이다. */
final class PcapBuilder {

    static final int MAGIC_MICROS = 0xA1B2C3D4;
    static final int MAGIC_NANOS  = 0xA1B23C4D;
    static final int MAGIC_BIG_ENDIAN = 0xD4C3B2A1;
    static final int MAGIC_PCAPNG = 0x0A0D0D0A;

    private final ByteArrayOutputStream out = new ByteArrayOutputStream();

    static PcapBuilder ethernet() { return new PcapBuilder(1, MAGIC_MICROS, 65535); }
    static PcapBuilder withMagic(int magic) { return new PcapBuilder(1, magic, 65535); }
    static PcapBuilder withLinkType(int linkType) { return new PcapBuilder(linkType, MAGIC_MICROS, 65535); }
    static PcapBuilder withSnaplen(int snaplen) { return new PcapBuilder(1, MAGIC_MICROS, snaplen); }

    private PcapBuilder(int linkType, int magic, int snaplen) {
        ByteBuffer h = ByteBuffer.allocate(24).order(ByteOrder.LITTLE_ENDIAN);
        h.putInt(magic).putShort((short) 2).putShort((short) 4)
         .putInt(0).putInt(0).putInt(snaplen).putInt(linkType);
        out.writeBytes(h.array());
    }

    /** 온전한 패킷 — incl_len == orig_len */
    PcapBuilder packet(int seconds, int micros, byte[] payload) {
        return packet(seconds, micros, payload, payload.length);
    }

    /** 절단된 패킷 — incl_len(실제 저장) < orig_len(원본) */
    PcapBuilder packet(int seconds, int micros, byte[] stored, int originalLength) {
        ByteBuffer h = ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN);
        h.putInt(seconds).putInt(micros).putInt(stored.length).putInt(originalLength);
        out.writeBytes(h.array());
        out.writeBytes(stored);
        return this;
    }

    /** 손상·악의적 파일 — 선언 길이가 실제 잔여보다 크다 */
    PcapBuilder packetWithDeclaredLength(int seconds, int micros, byte[] stored, int declaredInclLen) {
        ByteBuffer h = ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN);
        h.putInt(seconds).putInt(micros).putInt(declaredInclLen).putInt(declaredInclLen);
        out.writeBytes(h.array());
        out.writeBytes(stored);
        return this;
    }

    byte[] build() { return out.toByteArray(); }
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
    // ByteBuffer.getInt() 는 부호 있는 int 다. 마스킹·상한 검사가 없으면
    // NegativeArraySizeException 이나 OutOfMemoryError 로 터진다 — 정의된 실패가 아니다.
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
```

- [ ] **Step 3: 실패 확인**

Run: `mvn -pl pcap test`
Expected: 컴파일 실패

- [ ] **Step 4: 구현**

```java
/** @param truncated incl_len < orig_len — 캡처가 잘렸다. 하류는 이 스트림을 온전한 것으로 취급하면 안 된다. */
public record CapturedPacket(Instant at, byte[] data, int originalLength) {
    public boolean truncated() { return data.length < originalLength; }
}
```

`PcapReader`:
- `read(byte[])`와 `read(Path)`(= `Files.readAllBytes` 후 위임) 둘을 노출한다. 1차는 전체 로딩만 하고 스트리밍은 범위 밖이다.
- 매직을 네 가지로 **식별해서** 거부한다 — `0xA1B2C3D4`만 진행, `0xD4C3B2A1`은 "빅엔디언", `0xA1B23C4D`는 "나노초 해상도", `0x0A0D0D0A`는 "pcapng"라고 메시지에 적는다.
- 링크타입 1(Ethernet)만 허용.
- `ts_sec`·`ts_usec`·`incl_len`·`orig_len`은 **모두** `& 0xFFFFFFFFL`로 unsigned 해석한다. `incl_len`이 잔여 바이트 수를 넘으면 `PcapException`.

- [ ] **Step 5: 통과 확인**

Run: `mvn -pl pcap test`
Expected: `Tests run: 12, Failures: 0`

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
/**
 * Ethernet(14) + IPv4(20 + options) + TCP(20 + options) 프레임을 조립한다.
 * 체크섬은 0으로 둔다 — 리더가 검증하지 않는다(손상 탐지는 이 도구의 목적이 아니다).
 *
 * @param ethPadTo   이 길이에 못 미치면 0으로 채운다. 이더넷 최소 프레임(60) 재현용.
 */
static byte[] ethernetIpv4Tcp(String srcIp, int srcPort, String dstIp, int dstPort,
                              long seq, byte[] payload, int ipOptionBytes, int tcpOptionBytes,
                              int ethPadTo) { ... }

/** VLAN 태그(802.1Q, ethertype 0x8100)를 끼운 변형. */
static byte[] vlanTagged(String srcIp, int srcPort, String dstIp, int dstPort, long seq, byte[] payload) { ... }

/** UDP 프레임 — 대상이 아님을 확인하는 용도. */
static byte[] ethernetIpv4Udp(String srcIp, int srcPort, String dstIp, int dstPort, byte[] payload) { ... }

/** 단편화된 IPv4 — fragment offset != 0 이라 TCP 헤더가 없다. */
static byte[] ipv4Fragment(String srcIp, String dstIp, int fragmentOffset, byte[] payload) { ... }
```

구현 지침: IPv4 헤더의 `totalLength`는 **IP 헤더부터 페이로드 끝까지**의 실제 길이를 적는다(패딩 제외). IHL·dataOffset은 옵션 바이트 수에 맞춰 계산한다.

- [ ] **Step 2: 실패하는 테스트 작성**

테스트 헬퍼: `private TcpSegment decodeSingle(byte[] frame)` — 프레임 하나를 pcap 으로 감싸 `PcapReader` → `FrameDecoder`를 태우고 유일한 세그먼트를 돌려준다.

```java
@Test
void TCP_세그먼트의_4튜플과_페이로드를_뽑는다() { /* 10.0.1.20:40000 → 10.0.2.11:502, seq 1000, "abc" */ }

@Test
void 이더넷_패딩이_페이로드에_섞이지_않는다() {
    // 짧은 프레임은 60바이트로 패딩된다. 캡처 잔여 바이트로 자르면 0바이트가 스트림에 섞이고,
    // 그 0들이 MBAP 길이 필드 경계 탐색을 어긋나게 한다.
    byte[] frame = PcapBuilder.ethernetIpv4Tcp("10.0.1.20", 40000, "10.0.2.11", 502,
        1000, new byte[]{1, 2, 3}, 0, 0, /* ethPadTo */ 60);
    TcpSegment s = decodeSingle(frame);
    assertArrayEquals(new byte[]{1, 2, 3}, s.payload());
}

@Test
void IP_옵션이_있어도_헤더_길이를_보고_페이로드를_찾는다() { /* ipOptionBytes = 4 */ }

@Test
void TCP_옵션이_있어도_데이터_오프셋을_보고_페이로드를_찾는다() { /* tcpOptionBytes = 12 */ }

@Test
void VLAN_태그가_붙어도_해독한다() {
    // 산업망에서는 VLAN 이 오히려 기본이다. 조용히 건너뛰면
    // VLAN 캡처 전체가 사라지고 "위반 0건" 이 나온다 — 설계 §7 이 위험하다고 못박은 상황이다.
}

@Test
void IPv4가_아니면_대상_외로_센다() { /* ARP 등 */ }

@Test
void TCP가_아니면_대상_외로_센다() { /* UDP */ }

@Test
void 단편화된_조각은_대상_외로_센다() {
    // fragment offset != 0 인 조각에는 TCP 헤더가 없다. 있다고 가정하고 파싱하면 쓰레기를 읽는다.
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
void 대상_외_패킷_수를_보고한다() {
    // "아무것도 못 읽었다" 를 드러내려면 건너뛴 수를 알아야 한다.
    DecodedFrames d = FrameDecoder.decode(packets);
    assertEquals(2, d.skipped());
}
```

- [ ] **Step 3: 실패 확인**

Run: `mvn -pl pcap test`
Expected: 컴파일 실패

- [ ] **Step 4: 구현**

```java
public record TcpSegment(
    Instant at, String sourceAddress, int sourcePort,
    String targetAddress, int targetPort, long sequence, byte[] payload, boolean truncated) {}
```

```java
/** @param skipped 산업 트래픽 대상이 아니어서 건너뛴 패킷 수(ARP·UDP·단편·잘린 프레임). */
public record DecodedFrames(List<TcpSegment> segments, int skipped) {}
```

`FrameDecoder.decode(List<CapturedPacket>) → DecodedFrames`:
- ethertype은 오프셋 12에서 읽는다. `0x0800`이면 IPv4. **`0x8100`(또는 `0x88A8`)이면 802.1Q 태그이며, 그 다음 ethertype은 오프셋 16에 있다** — 태그 4바이트 중 앞 2바이트가 이미 읽은 TPID다. 이중 태그(QinQ)가 있으므로 **`if`가 아니라 반복**으로 벗긴다(그러지 않으면 이중 태그 트래픽이 통째로 사라져 fix 의 취지가 무너진다)
- IPv4 프로토콜 6(TCP)만. **fragment offset ≠ 0 이거나 MF 플래그가 서 있으면** 건너뛴다 — 첫 조각도 페이로드가 잘려 있어 프레임 경계를 믿을 수 없다
- **`payload = totalLength − IHL*4 − dataOffset*4`** 로 길이를 유도한다. **유도 길이가 실제 남은 바이트보다 크면 있는 만큼만 잘라내고 `truncated = true`** 로 둔다(snaplen 절단의 정상 경로다). 유도 길이가 음수이거나 `IHL < 5` · `dataOffset < 5` 이면 `skipped`
- `sequence`는 `& 0xFFFFFFFFL`
- `CapturedPacket.truncated()`를 `TcpSegment.truncated`로 전파한다
- 어떤 이유로든 대상이 아니면 `skipped`를 올린다(예외를 던지지 않는다)

- [ ] **Step 5: 통과 확인**

Run: `mvn -pl pcap test`
Expected: `Tests run: 23, Failures: 0` (`PcapReaderTest` 12 + `FrameDecoderTest` 11)

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

테스트 헬퍼 둘: `private TcpSegment seg(long seq, String payload)` — 고정된 4-tuple 로 세그먼트 하나를 만든다(`at`은 seq 순으로 증가). `private TcpSegment syn(long seq)` — SYN 플래그가 선 길이 0 세그먼트. `private TcpStream assemble(TcpSegment... segs)` — `TcpStreamAssembler.assemble(List.of(segs))`의 첫 스트림.

```java
@Test
void 순서대로_온_세그먼트를_이어붙인다() { /* seq 100 "abc", seq 103 "def" → "abcdef" */ }

@Test
void 순서가_뒤바뀌어도_seq로_정렬한다() { /* 103 먼저, 100 나중 */ }

@Test
void SYN을_보면_바이트는_버리되_sawSyn을_기록한다() {
    // 길이 0 세그먼트를 통째로 버리면 클라이언트를 확정할 유일한 신호가 사라진다.
    assertTrue(assemble(syn(1000), seg(1001, "abc")).sawSyn());
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
void 방향마다_별개_스트림이다() { /* A→B 와 B→A 가 둘 */ }

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
void 절단된_세그먼트가_있으면_스트림을_절단으로_표시한다() { /* truncated 전파 */ }

@Test
void 스트림_열거_순서는_최초_등장_순서다() {
    // HashMap 이면 리포트가 비결정적이 된다. 비결정성의 발원지가 이 층이다.
}

@Test
void 같은_입력에_같은_스트림_목록이_나온다() { /* 두 번 조립해 동일 */ }
```

- [ ] **Step 2: 실패 확인**

Run: `mvn -pl pcap test`
Expected: 컴파일 실패

- [ ] **Step 3: 구현**

```java
/**
 * 한 방향의 재조립된 바이트 흐름.
 *
 * @param at        이 방향에서 관찰된 첫 세그먼트의 캡처 시각. Observation.at 이 여기서 온다.
 * @param truncated 이 방향의 세그먼트 중 하나라도 절단됐으면 true. 스트림 전체를 온전한 것으로 취급하면 안 된다.
 * @param sawSyn    이 방향에서 SYN 을 봤다. 청크 3 의 클라이언트 판정이 이 값을 우선 근거로 쓴다.
 */
public record TcpStream(
    Instant at, String sourceAddress, int sourcePort, String targetAddress, int targetPort,
    byte[] contiguousPrefix, boolean hasGap, boolean truncated, boolean sawSyn) {}
```

`TcpStreamAssembler.assemble(List<TcpSegment>) → List<TcpStream>`:
- 키는 `(srcAddr, srcPort, dstAddr, dstPort)` — 방향이 다르면 다른 키다
- **`LinkedHashMap`** 으로 모아 최초 등장 순서를 유지한다
- 길이 0 세그먼트는 **바이트를 버리되**, SYN 플래그가 서 있으면 그 방향의 `sawSyn`을 세운다. 그 외 길이 0 세그먼트(순수 ACK·FIN)는 키 등록도 하지 않는다
- `truncated`는 **그 방향 세그먼트 중 하나라도 절단됐으면** true. 절단된 세그먼트의 (짧은) 페이로드도 `contiguousPrefix`에 그대로 기여한다 — 버리면 갭이 되어 오히려 더 잃는다
- 각 스트림에서 최소 seq를 base로 잡고, seq 순으로 이어붙이되 **이미 채워진 오프셋은 덮어쓰지 않는다**(first-wins)
- 첫 갭에서 멈추고 그때까지를 `contiguousPrefix`로, `hasGap = true`로 둔다

- [ ] **Step 4: 통과 확인**

Run: `mvn -pl pcap test`
Expected: `Tests run: 35, Failures: 0` (12 + 11 + 12)

- [ ] **Step 5: 커밋**

```bash
git add pcap/src
git commit -m "feat: TCP 스트림 재조립 — SYN 기록, 갭 이후는 UNDECIDABLE"
```

---

## Chunk 3: Modbus 해독과 배선

이 청크의 결정 셋을 먼저 못박는다.

| 결정 | 값 | 이유 |
|---|---|---|
| MBAP 길이 필드 의미 | `length = 유닛ID(1) + PDU 길이`. **다음 프레임 = 오프셋 + 6 + length**, 유효 범위는 **2 ≤ length ≤ 254** | 오해하면 두 번째 프레임부터 전부 깨진다. 최소 PDU 는 함수코드 1바이트이므로 하한이 1이 아니라 2다 |
| 요청/응답 | **요청만 `Observation`이 된다** (설계 §5-⑤) | 응답은 출발지·목적지가 뒤집혀 있어 관찰하면 정상 통신이 전부 위반이 된다 |
| 산업 프로토콜이 아닌 스트림 | 유효 프레임 **0개면 대상 외**, 1개 이상이면 그 안의 잔여 바이트만 `UNDECIDABLE` | 그러지 않으면 SSH·HTTP가 전부 `UNDECIDABLE`로 계수되어 커버리지 지표가 캡처 구성에 지배된다 |
| 절단·갭 vs 대상 외의 우선순위 | **`isModbusStream == false`가 이긴다** | `tcpdump -s 96` 같은 환경에서는 SSH 스트림도 전부 절단이다. 절단이 이기면 위 결정이 무력해진다 |

### Task 9: MBAP 프레이밍

**Files:**
- Create: `decode/src/main/java/dev/krillin/huginn/decode/ModbusFrame.java`
- Create: `decode/src/main/java/dev/krillin/huginn/decode/FramingResult.java`
- Create: `decode/src/main/java/dev/krillin/huginn/decode/ModbusFramer.java`
- Test: `decode/src/test/java/dev/krillin/huginn/decode/ModbusFramerTest.java`

MBAP: 트랜잭션ID(2) · 프로토콜ID(2, **반드시 0**) · 길이(2) · 유닛ID(1) · PDU.

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
git commit -am "feat: Modbus 함수코드 → Access, 43은 MEI를 보지 않으므로 UNDECIDABLE"
```

---

### Task 11: `objectRef` 생성

**Files:**
- Create: `decode/src/main/java/dev/krillin/huginn/decode/ModbusObjectRef.java`
- Test: `decode/src/test/java/dev/krillin/huginn/decode/ModbusObjectRefTest.java`

`Observation.objectRef`는 근거 표시용이며 판정에는 쓰지 않는다. 그래도 리포트에서 "무엇을 건드렸는가"가 없으면 운영자가 조치할 수 없다.

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

테스트 헬퍼: `private byte[] pdu(int startAddress, int quantity)` — 두 값을 빅엔디언 2바이트씩 이어 붙인 4바이트 배열(함수코드는 포함하지 않는다).

- [ ] **Step 4: 통과 확인**

Run: `mvn -pl decode -am test`
Expected: `decode` 모듈 `Tests run: 40, Failures: 0` (33 + `ModbusObjectRefTest` 7)

- [ ] **Step 5: 커밋**

```bash
git commit -am "feat: objectRef — 무엇을 건드렸는지 근거에 남긴다"
```

---

### Task 12: `ModbusObserver` — 스트림에서 요청만 관찰한다

**Files:**
- Create: `decode/src/main/java/dev/krillin/huginn/decode/ModbusObserver.java`
- Create: `decode/src/main/java/dev/krillin/huginn/decode/ObservationResult.java`
- Test: `decode/src/test/java/dev/krillin/huginn/decode/ModbusObserverTest.java`

**요청/응답 판정 규칙 — 근거를 순서대로 쓴다.**

한 대화는 4-tuple을 뒤집은 두 스트림으로 이루어진다. 둘 중 **클라이언트 쪽만** `Observation`을 만든다.

| 순위 | 근거 | 판정 |
|---|---|---|
| 1 | `sawSyn` | SYN을 보낸 쪽이 클라이언트다. 유일하게 확정적인 신호다 |
| 2 | 양쪽 다 프레임이 있고 SYN이 없음 | `TcpStream.at`이 이른 쪽. 같으면 3순위로 |
| 3 | 시각이 같음 | **목적지 포트가 낮은 쪽**을 서버로 본다(관례상 502). §5-①은 *프로토콜* 판정에 포트를 쓰지 말라는 것이지 방향 판정을 금하지 않는다 |
| 4 | **한 방향에만 프레임이 있고 SYN도 없음** | **판정 불가 → `UNDECIDABLE` 관찰 한 건.** 관찰로 만들지 않는다 |

**4순위가 이 규칙의 핵심이다.** "먼저 보낸 쪽"만으로 판정하면 한 방향만 잡힌 캡처에서 그 방향이 자동으로 "먼저"가 된다. 서버→클라이언트만 잡힌 캡처(비대칭 SPAN, PLC를 출발지로 건 BPF 필터, 요청 이후에 시작된 캡처)에서 **응답을 요청으로 읽고, FC 16 응답이 `WRITE`가 되고, PLC가 미등록 출발지가 되어 HIGH 오탐**이 난다. 설계 §5-⑤의 "서버 쪽을 판정할 수 없는 스트림은 `UNDECIDABLE`"이 정확히 이 경우를 가리킨다.

- [ ] **Step 1: 실패하는 테스트 작성**

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
void 관찰_시각은_스트림의_첫_세그먼트_시각이다() { /* ... */ }

@Test
void 한_스트림의_프레임_여러_개가_각각_관찰이_된다() { /* ... */ }

@Test
void Modbus가_아닌_스트림은_관찰도_미해독도_아니다() {
    // SSH 스트림 하나만 있는 캡처 → 관찰 0, UNDECIDABLE 0, 대상 외 1
    ObservationResult r = observe(sshStream);
    assertTrue(r.observations().isEmpty());
    assertEquals(0, r.undecidableStreams());
    assertEquals(1, r.skippedStreams());
}

@Test
void Modbus_스트림_안의_미해독_바이트는_UNDECIDABLE_관찰을_만든다() { /* ... */ }

@Test
void 갭이_있는_스트림은_연속_구간만_해독하고_나머지는_UNDECIDABLE이다() { /* ... */ }

@Test
void SYN이_있으면_그_방향을_클라이언트로_본다() {
    // 양방향 모두 프레임이 있어도 SYN 이 확정적 근거다.
}

@Test
void 한_방향만_잡힌_캡처는_요청으로_단정하지_않는다() {
    // 서버→클라이언트만 잡힌 캡처를 요청으로 읽으면 응답의 FC 16 이 WRITE 가 되고
    // PLC 가 미등록 출발지가 되어 HIGH 오탐이 난다.
    ObservationResult r = observe(responseOnlyStream);
    assertTrue(r.observations().stream().allMatch(o -> o.access() == Access.UNDECIDABLE));
}

@Test
void 절단된_비Modbus_스트림은_대상_외가_이긴다() {
    // tcpdump -s 96 환경에서는 SSH 스트림도 전부 절단이다.
    // 절단이 이기면 커버리지 지표가 다시 비산업 트래픽에 지배된다.
    ObservationResult r = observe(truncatedSshStream);
    assertEquals(0, r.undecidableStreams());
    assertEquals(1, r.skippedStreams());
}

@Test
void 절단된_스트림은_UNDECIDABLE_관찰을_함께_남긴다() { /* snaplen 절단 */ }
```

- [ ] **Step 2: 실패 확인**

Run: `mvn -pl decode -am test`
Expected: 컴파일 실패 — `ModbusObserver` 없음

- [ ] **Step 3: 구현**

```java
/**
 * @param decodedStreams    유효 프레임을 뽑아 관찰로 만든 스트림 수
 * @param undecidableStreams Modbus 스트림이지만 일부 또는 전부를 해독하지 못한 수
 * @param skippedStreams    산업 트래픽이 아니어서 대상에서 제외한 스트림 수
 */
public record ObservationResult(
    List<Observation> observations, int decodedStreams, int undecidableStreams, int skippedStreams) {}
```

진입점: `ModbusObserver.observe(List<TcpStream> streams) → ObservationResult`.

1. 각 스트림에 `ModbusFramer.frames(stream.contiguousPrefix())`를 돌린다
2. `isModbusStream == false`면 **절단·갭 여부와 무관하게** `skippedStreams`를 올리고 끝낸다(우선순위 표)
3. 남은 스트림을 4-tuple을 뒤집어 짝지어 대화로 묶는다. 짝이 없으면 단방향 대화다
4. 위 판정 표로 클라이언트 방향을 고른다. 4순위면 `Access.UNDECIDABLE` 관찰 한 건을 만들고 `undecidableStreams`를 올린다
5. 클라이언트 방향의 각 프레임을 `Observation`으로 만든다 — `at`은 `TcpStream.at`, `source`/`target`은 그 스트림의 4-tuple, `access`는 `ModbusAccess.of(fc)`, `objectRef`는 `ModbusObjectRef.of(fc, pdu)`
6. `undecodedBytes > 0`이거나 `hasGap`이거나 `truncated`면 그 스트림에 `UNDECIDABLE` 관찰을 **한 건 더** 붙이고 `undecidableStreams`를 올린다. 이때 `source`/`target`은 그 스트림의 것, `objectRef`는 `"-"`

- [ ] **Step 4: 통과 확인**

Run: `mvn -pl decode -am test`
Expected: `decode` 모듈 `Tests run: 50, Failures: 0` (40 + `ModbusObserverTest` 10)

- [ ] **Step 5: 커밋**

```bash
git commit -am "feat: 요청만 관찰한다 — 응답을 관찰하면 정상 통신이 전부 위반이 된다"
```

---

### Task 13: 파이프라인과 CLI

**Files:**
- Create: `cli/src/main/java/dev/krillin/huginn/cli/Pipeline.java`
- Create: `cli/src/main/java/dev/krillin/huginn/cli/Report.java`
- Create: `cli/src/main/java/dev/krillin/huginn/cli/Huginn.java`
- Modify: `cli/pom.xml` — shade 플러그인으로 실행 가능 jar
- Test: `cli/src/test/java/dev/krillin/huginn/cli/EndToEndTest.java`

세 층으로 나눈다 — `main`이 `System.exit`을 부르면 테스트에서 JVM 이 죽는다.

```java
public static void main(String[] args) { System.exit(run(args)); }
public static int run(String[] args)      // 인자 검증 · 파일 읽기 · 예외 → 종료 코드. 테스트는 이것을 부른다
Report Pipeline.run(byte[] pcap, String policyYaml)  // 순수 실행
```

`PcapException`·`PolicyException`은 `Huginn.run`이 잡아 **2**로 매핑한다.

**종료 코드:** 0 = 위반 없음, 1 = 위반 있음, 2 = 사용법·입력·계약 오류. **`UNDECIDABLE`이 많아도 위반이 0이면 0을 낸다** — 커버리지는 리포트가 항상 내므로 종료 코드까지 흐리지 않는다.

**리포트 형식:**

```
Huginn — 통신 대사 결과
  처리 패킷        1,284
  대상 외 패킷        112
  해독한 대화           6
  대상 외 대화          3
  UNDECIDABLE 대화     1

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
void 비표준_포트의_우회를_잡는다() { /* 502 가 아닌 포트로 같은 통신 */ }

@Test
void 포트가_502여도_프레이밍이_아니면_Modbus로_치지_않는다() { /* §5-① 을 양방향으로 고정 */ }

@Test
void 리포트는_커버리지를_함께_낸다() {
    Report r = Pipeline.run(capture, policy);
    String out = r.render();
    assertTrue(out.contains("처리 패킷"));
    assertTrue(out.contains("해독한 대화"));
    assertTrue(out.contains("UNDECIDABLE"));
}

@Test
void 비산업_트래픽은_UNDECIDABLE이_아니라_대상_외로_센다() {
    // 이 구분이 없으면 커버리지 지표가 캡처의 SSH·HTTP 양에 지배된다.
}

@Test
void 계약이_잘못되면_종료코드_2다() { /* 위반 1 과 구별된다 */ }

@Test
void 같은_입력에_같은_리포트가_나온다() { /* 문자열 동일 */ }
```

- [ ] **Step 2: 실패 확인**

Run: `mvn -pl cli -am test`
Expected: 컴파일 실패

- [ ] **Step 3: 구현**

`Pipeline.run`이 커버리지를 직접 집계한다 — `PcapReader`(처리 패킷 수), `FrameDecoder`(대상 외 패킷), `ModbusObserver`(해독·대상 외·UNDECIDABLE 대화), `Reconciler`(위반). `ReconcileResult`에는 패킷 수를 담을 자리가 없으므로 `Report`가 둘을 합쳐 든다.

`cli/pom.xml`에 shade 플러그인을 붙여 `huginn.jar` 하나로 실행되게 한다(`mainClass`는 `dev.krillin.huginn.cli.Huginn`).

- [ ] **Step 4: 통과 확인**

Run: `mvn test`
Expected: 전체 `BUILD SUCCESS`, `cli` 모듈 `Tests run: 8, Failures: 0`

- [ ] **Step 5: 커밋**

```bash
git add cli/src cli/pom.xml
git commit -m "feat: 파이프라인과 CLI — 리포트는 커버리지를 함께 낸다"
```

---

### Task 14: 공개 캡처로 반증 조건을 실제로 시험한다

**Files:**
- Create: `scripts/fetch-samples.sh`, `scripts/fetch-samples.ps1`
- Create: `samples/README.md`
- Create: `samples/.gitignore` — 내려받은 캡처는 커밋하지 않는다

설계 §10의 첫 반증 조건은 *"공개 ICS 캡처에서 `UNDECIDABLE` 비율이 압도적이면 Modbus 단독으로 유의미한 판정이 된다는 전제가 틀린 것"*이다. **내려받기만 하고 실행하지 않으면 이 조건은 한 번도 시험되지 않는다.**

- [ ] **Step 1: 내려받기 스크립트 작성**

출처와 SHA-256을 스크립트에 명시한다(4SICS ICS Lab, Netresec 공개 캡처 등). 주 개발 환경이 Windows이므로 `.ps1`을 함께 둔다. 캡처는 **저장소에 넣지 않는다**(라이선스가 제각각).

**pcapng는 `PcapReader`가 거부한다.** 받은 파일이 pcapng이면 스크립트가 `editcap -F pcap`으로 정규화한다 — 그러지 않으면 캡처를 한 건도 못 읽어 반증 조건이 또 시험되지 않는다.

Run: `bash scripts/fetch-samples.sh` (또는 `pwsh scripts/fetch-samples.ps1`)
Expected: `samples/` 아래에 `.pcap` 파일들이 생기고 해시 검증이 전부 통과

- [ ] **Step 2: 실행하고 결과를 기록**

내려받은 각 캡처에 Huginn을 돌려 커버리지 다섯 수치를 `samples/README.md`에 표로 기록한다. 정책 파일은 캡처에서 관찰된 통신 중 일부만 선언해 위반이 나오는 형태로 만든다.

Run: `mvn -DskipTests package && java -jar cli/target/huginn.jar samples/<capture>.pcap samples/<capture>-policy.yaml`
Expected: 리포트가 출력되고 종료 코드가 0 또는 1(2가 나오면 입력·계약 문제이므로 먼저 해결한다)

- [ ] **Step 3: 반증 조건 판정**

`UNDECIDABLE` 비율이 높으면 원인을 적는다 — 프로토콜 선택이 틀렸는가, 요청/응답 판정이 4순위(판정 불가)로 빠졌는가, 캡처가 대화 중간부터 시작하는가. **판정 결과를 설계 문서 §10에 반영한다.**

Expected: `samples/README.md`에 캡처별 다섯 수치와 판정 한 줄이 기록되어 있다

- [ ] **Step 4: 커밋**

```bash
git add scripts samples
git commit -m "test: 공개 ICS 캡처로 반증 조건을 시험한다"
```

---

### Task 15: README와 예시

**Files:**
- Create: `README.md`
- Create: `examples/policy.yaml`
- Create: `LICENSE` — Bifrost에서 복사(Apache-2.0)

- [ ] **Step 1: LICENSE 복사**

```bash
test -f ../bifrost/LICENSE && cp ../bifrost/LICENSE LICENSE
```

형제 저장소가 없으면 Apache-2.0 전문을 직접 받는다.
Expected: `LICENSE` 파일이 202줄이고 첫 줄이 `Apache License`

- [ ] **Step 2: 예시 정책 작성**

`examples/policy.yaml` — 설계 §4의 예시를 그대로 두되 **로딩에 성공하는 형태**여야 한다(모든 `from`/`to`가 `peers`에 선언되어 있을 것).

**예시가 썩지 않도록 테스트로 고정한다.** `cli/src/test/.../ExamplePolicyTest.java`에 저장소의 `examples/policy.yaml`을 읽어 `PolicyLoader.parse`가 성공하는지 확인하는 테스트 한 건을 둔다.

Run: `mvn -pl cli test`
Expected: `cli` 모듈 `Tests run: 9, Failures: 0`

- [ ] **Step 3: README 작성**

Bifrost README의 톤을 따른다 — 무엇을 관찰하는지, **무엇을 하지 않는지**, 그리고 모든 주장에 대응하는 테스트가 무엇인지.

핵심 문장: *"fail-closed는 길목을 지나는 것만 막는다. Huginn은 지나지 않은 것을 본다."*

"하지 않는 것"에 다음을 명시한다 — 라이브 캡처, 능동 스캔, OPC UA·Sparkplug, 자동 차단, 절대 성능 주장, **게이트웨이 뒤 유닛ID 단위 판정**(정책이 IP 기준이라 게이트웨이 경유 우회는 보이지 않는다).

- [ ] **Step 4: 커밋**

```bash
git add README.md LICENSE examples
git commit -m "docs: README와 예시 정책"
```

---

## 완료 조건

- [ ] `mvn test` 전체 통과
- [ ] **`decode` 밖 어디에도 MBAP·PDU·함수코드를 다루는 코드가 없다** (`Protocol.MODBUS_TCP`라는 *이름*은 정책 계약이 쓰므로 `reconcile`·`contract`에 있는 것이 정상이다)
- [ ] `pcap`·`decode`·`reconcile` 모듈에 런타임 서드파티 의존이 없다
- [ ] 리포트가 커버리지 다섯 수치(처리 패킷·대상 외 패킷·해독한 대화·대상 외 대화·`UNDECIDABLE` 대화)를 항상 낸다
- [ ] 위반이 든 합성 캡처에서 실제로 잡힌다 — 정상 캡처에서 0건인 것만으로는 증명되지 않는다
- [ ] **요청과 응답이 모두 든 정상 캡처에서 위반이 0건이다** — 요청/응답 결함의 회귀 가드
- [ ] **한 방향만 잡힌 캡처가 위반이 아니라 `UNDECIDABLE`로 나온다** — 클라이언트 판정 4순위의 회귀 가드
- [ ] `java -jar cli/target/huginn.jar <capture> <policy>`가 실제로 실행되고 종료 코드가 0/1/2 계약을 지킨다
- [ ] 공개 ICS 캡처로 설계 §10의 반증 조건을 실제로 시험하고 결과를 기록했다
