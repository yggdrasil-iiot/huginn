# Huginn 1차 (Modbus/TCP) 구현 계획

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** pcap 파일에서 Modbus/TCP 통신을 해독해 선언된 `CommunicationPolicy`와 대조하고, 미등록 통신을 근거와 함께 보고하는 CLI를 만든다.

**Architecture:** 이음매(`Observation`)를 먼저 고정하고 아래로 내려간다. 순수 대사 로직 → pcap 읽기 → Modbus 해독 순. `decode` 밖은 프로토콜을 모르며, 그 경계가 제대로 잡혔는지는 2차에 S7comm을 붙일 때 드러난다. pcap·프로토콜 파싱은 외부 의존 없이 직접 구현해 테스트가 환경을 타지 않게 한다.

**Tech Stack:** Java 17 · Maven 멀티모듈 · JUnit 5.10.3 · Jackson(계약 파일 한정) · 그 외 런타임 의존 없음

**설계 문서:** `docs/superpowers/specs/2026-09-05-huginn-design.md`

---

## 파일 구조

| 모듈 | 책임 | 외부 의존 |
|---|---|---|
| `contract/` | `CommunicationPolicy` 로딩·검증 | Jackson(YAML) |
| `reconcile/` | `Observation` 이음매, 대사, `Finding` | **없음** |
| `pcap/` | pcap 파일 → 패킷 → TCP 스트림 | **없음** |
| `decode/` | Modbus/TCP 프레이밍·함수코드 → `Observation` | **없음** |
| `cli/` | 배선·리포트 | 위 전부 |

`reconcile`이 `Observation`을 소유한다 — 이음매의 주인은 그것을 소비하는 쪽이어야 `decode`가 `reconcile`에 의존하는 한 방향이 유지된다.

---

## Chunk 1: 이음매와 대사

바이너리를 만지기 전에 순수 로직부터 세운다. 이 청크가 끝나면 `Observation` 목록과 정책 파일만으로 대사가 돌아간다.

### Task 1: Maven 골격

**Files:**
- Create: `pom.xml`, `contract/pom.xml`, `reconcile/pom.xml`, `pcap/pom.xml`, `decode/pom.xml`, `cli/pom.xml`

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
      </plugins>
    </pluginManagement>
  </build>
</project>
```

- [ ] **Step 2: 모듈 POM 5개 작성**

각 모듈은 부모만 상속하고 필요한 것만 더한다. `reconcile`·`pcap`·`decode`는 **의존성을 추가하지 않는다**(JUnit은 부모에서 상속). 예시 — `reconcile/pom.xml`:

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

`contract`는 여기에 `jackson-dataformat-yaml` + `jackson-databind` + `huginn-reconcile`(Protocol/Access 열거형을 쓰므로)을 더한다.
`decode`는 `huginn-reconcile` + `huginn-pcap`.
`cli`는 네 모듈 전부.

- [ ] **Step 3: 빌드 확인**

Run: `mvn -q -DskipTests compile`
Expected: BUILD SUCCESS. 소스가 없어도 5개 모듈이 인식되어야 한다.

- [ ] **Step 4: 커밋**

```bash
git add pom.xml */pom.xml
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

Run: `mvn -q -pl reconcile test`
Expected: 컴파일 실패 — `Endpoint` 없음

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

/** 해독한 산업 프로토콜. 1차는 Modbus 하나뿐이며, 2차에 S7COMM 이 붙어도 이 밖은 바뀌지 않아야 한다. */
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
 * @param objectRef 건드린 대상의 프로토콜별 정규화 표기(예: Modbus "holding:40001"). 근거 표시용이며 판정에는 쓰지 않는다.
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

Run: `mvn -q -pl reconcile test`
Expected: PASS

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
        assertEquals("10.0.1.20", p.addressOf("hmi-01"));
        assertTrue(p.allows("10.0.1.20", "10.0.2.11", Protocol.MODBUS_TCP, Access.WRITE));
        assertFalse(p.allows("10.0.1.20", "10.0.2.11", Protocol.MODBUS_TCP, Access.CONTROL));
    }

    @Test
    void 알_수_없는_peer를_참조하면_즉시_실패한다() {
        String bad = VALID.replace("to: plc-mixer", "to: ghost");
        PolicyException e = assertThrows(PolicyException.class, () -> PolicyLoader.parse(bad));
        assertTrue(e.getMessage().contains("ghost"));
    }

    @Test
    void peer_id가_중복되면_즉시_실패한다() {
        String bad = VALID.replace("id: plc-mixer", "id: hmi-01");
        assertThrows(PolicyException.class, () -> PolicyLoader.parse(bad));
    }

    @Test
    void 지원하지_않는_version이면_즉시_실패한다() {
        assertThrows(PolicyException.class, () -> PolicyLoader.parse(VALID.replace("version: 1", "version: 2")));
    }

    @Test
    void 알_수_없는_필드가_있으면_즉시_실패한다() {
        assertThrows(PolicyException.class, () -> PolicyLoader.parse(VALID + "unexpected: true\n"));
    }
}
```

- [ ] **Step 2: 실패 확인**

Run: `mvn -q -pl contract -am test`
Expected: 컴파일 실패

- [ ] **Step 3: 구현**

`PolicyException`은 `RuntimeException` 하위. `PolicyLoader`는 Jackson YAML로 읽되 `FAIL_ON_UNKNOWN_PROPERTIES`를 켠다(기본값이 켜짐이므로 끄지 말 것). 파싱 후 검증을 직접 한다 — version, peer id 중복, allowed의 from/to 참조 무결성.

`CommunicationPolicy`는 조회 두 개만 노출한다.

```java
public String addressOf(String peerId);
public boolean allows(String sourceAddress, String targetAddress, Protocol protocol, Access access);
```

`allows`는 주소 기준이다 — 관찰에는 peer id 가 없고 IP 만 있다. 내부에서 주소→id 로 역인덱스를 만든다. `Access.UNDECIDABLE`이 들어오면 **항상 false**를 반환한다(해독 못 한 것을 허용으로 치지 않는다).

- [ ] **Step 4: 통과 확인**

Run: `mvn -q -pl contract -am test`
Expected: PASS (5개)

- [ ] **Step 5: 커밋**

```bash
git add contract/src contract/pom.xml
git commit -m "feat: CommunicationPolicy 로딩 — 계약 오류는 즉시 실패"
```

---

### Task 4: 대사기

**Files:**
- Create: `reconcile/src/main/java/dev/krillin/huginn/reconcile/Finding.java`
- Create: `reconcile/src/main/java/dev/krillin/huginn/reconcile/PolicyView.java`
- Create: `reconcile/src/main/java/dev/krillin/huginn/reconcile/Reconciler.java`
- Create: `reconcile/src/main/java/dev/krillin/huginn/reconcile/ReconcileResult.java`
- Test: `reconcile/src/test/java/dev/krillin/huginn/reconcile/ReconcilerTest.java`

`reconcile`은 `contract`에 의존하지 않는다(반대 방향이다). 대사기는 `PolicyView` 인터페이스만 알고, `contract`의 `CommunicationPolicy`가 그것을 구현한다.

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

Run: `mvn -q -pl reconcile test`
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

`Severity`는 `LOW < MEDIUM < HIGH` 순서의 열거형. `Finding`은 `record Finding(Severity severity, Kind kind, Observation evidence, String detail)`이며 `Kind`는 중첩 열거형 `{ UNDECLARED }`(1차는 한 종류로 시작한다 — 세분화는 근거가 생길 때).

`ReconcileResult`는 `record ReconcileResult(List<Finding> findings, int observedCount, int undecidableCount)`.

`Reconciler.reconcile`은 입력 순서를 유지하며 한 번 훑는다. `UNDECIDABLE`은 정책 조회를 하지 않고 계수만 한다. 심각도는 `WRITE`·`CONTROL` → `HIGH`, `READ` → `MEDIUM`.

- [ ] **Step 4: 통과 확인**

Run: `mvn -q -pl reconcile test`
Expected: PASS (8개)

- [ ] **Step 5: `CommunicationPolicy`가 `PolicyView`를 구현하도록 연결**

`contract` 모듈에서 `implements PolicyView`를 붙이고 `mvn -q test`로 전체 통과 확인.

- [ ] **Step 6: 커밋**

```bash
git add reconcile/src contract/src
git commit -m "feat: 대사기 — deny-by-default, UNDECIDABLE은 위반이 아니라 별도 계수"
```

---

## Chunk 2: pcap 읽기

바이너리 계층. **합성 pcap 빌더를 먼저 만든다** — 그것 없이는 아무것도 결정적으로 테스트할 수 없다.

### Task 5: 합성 pcap 빌더와 `PcapReader`

**Files:**
- Create: `pcap/src/main/java/dev/krillin/huginn/pcap/PcapReader.java`
- Create: `pcap/src/main/java/dev/krillin/huginn/pcap/CapturedPacket.java`
- Create: `pcap/src/main/java/dev/krillin/huginn/pcap/PcapException.java`
- Create: `pcap/src/test/java/dev/krillin/huginn/pcap/PcapBuilder.java` *(테스트 소스)*
- Test: `pcap/src/test/java/dev/krillin/huginn/pcap/PcapReaderTest.java`

- [ ] **Step 1: 빌더와 실패하는 테스트 작성**

`PcapBuilder`는 libpcap 파일 포맷을 손으로 조립한다 — 글로벌 헤더 24바이트(magic `0xA1B2C3D4`, 버전 2.4, 링크타입 1=Ethernet), 이어서 패킷마다 16바이트 헤더 + 데이터.

```java
package dev.krillin.huginn.pcap;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/** 테스트용 pcap 조립기. 외부 캡처 파일 없이 결정적으로 검증하기 위한 것이다. */
final class PcapBuilder {
    private final ByteArrayOutputStream out = new ByteArrayOutputStream();

    static PcapBuilder ethernet() { return new PcapBuilder(1, 0xA1B2C3D4); }
    static PcapBuilder withMagic(int magic) { return new PcapBuilder(1, magic); }
    static PcapBuilder withLinkType(int linkType) { return new PcapBuilder(linkType, 0xA1B2C3D4); }

    private PcapBuilder(int linkType, int magic) {
        ByteBuffer h = ByteBuffer.allocate(24).order(ByteOrder.LITTLE_ENDIAN);
        h.putInt(magic).putShort((short) 2).putShort((short) 4)
         .putInt(0).putInt(0).putInt(65535).putInt(linkType);
        out.writeBytes(h.array());
    }

    PcapBuilder packet(int seconds, int micros, byte[] payload) {
        ByteBuffer h = ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN);
        h.putInt(seconds).putInt(micros).putInt(payload.length).putInt(payload.length);
        out.writeBytes(h.array());
        out.writeBytes(payload);
        return this;
    }

    byte[] build() { return out.toByteArray(); }
}
```

테스트:

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
    assertEquals(Instant.ofEpochSecond(1_700_000_000, 500_000_000L), packets.get(0).at());
    assertArrayEquals(new byte[]{1, 2, 3}, packets.get(0).data());
}

@Test
void 매직넘버가_틀리면_즉시_실패한다() {
    assertThrows(PcapException.class, () -> PcapReader.read(PcapBuilder.withMagic(0xDEADBEEF).build()));
}

@Test
void 지원하지_않는_링크타입이면_즉시_실패한다() {
    // 부분 결과를 내면 "위반 0건" 이 안전으로 오독된다.
    assertThrows(PcapException.class, () -> PcapReader.read(PcapBuilder.withLinkType(228).build()));
}

@Test
void 잘린_파일은_즉시_실패한다() {
    byte[] full = PcapBuilder.ethernet().packet(1, 0, new byte[]{1, 2, 3, 4}).build();
    assertThrows(PcapException.class, () -> PcapReader.read(Arrays.copyOf(full, full.length - 2)));
}
```

- [ ] **Step 2: 실패 확인** — Run: `mvn -q -pl pcap test`

- [ ] **Step 3: 구현**

`CapturedPacket`은 `record CapturedPacket(Instant at, byte[] data)`. `PcapReader.read(byte[])`는 리틀엔디언 매직만 지원하고(빅엔디언 `0xD4C3B2A1`은 명시적으로 거부), 링크타입 1만 허용한다. 잘린 헤더·잘린 데이터는 `PcapException`.

- [ ] **Step 4: 통과 확인** — Expected: PASS (5개)

- [ ] **Step 5: 커밋**

```bash
git add pcap/src pcap/pom.xml
git commit -m "feat: pcap 리더와 합성 빌더 — 입력 오류는 즉시 실패"
```

---

### Task 6: Ethernet → IPv4 → TCP

**Files:**
- Create: `pcap/src/main/java/dev/krillin/huginn/pcap/TcpSegment.java`
- Create: `pcap/src/main/java/dev/krillin/huginn/pcap/LinkLayerDecoder.java`
- Test: `pcap/src/test/java/dev/krillin/huginn/pcap/LinkLayerDecoderTest.java`
- Modify: `pcap/src/test/java/dev/krillin/huginn/pcap/PcapBuilder.java` — 프레임 조립 헬퍼 추가

- [ ] **Step 1: 실패하는 테스트 작성**

빌더에 `ethernetIpv4Tcp(src, sport, dst, dport, seq, payload)`를 더한다(Ethernet 14B + IPv4 20B + TCP 20B).

```java
@Test
void TCP_세그먼트의_4튜플과_페이로드를_뽑는다() { /* ... */ }

@Test
void IPv4가_아니면_건너뛴다() {
    // 대상이 아닌 것과 해독 실패는 다르다 — 여기서는 조용히 건너뛴다.
}

@Test
void TCP가_아니면_건너뛴다() { /* UDP */ }

@Test
void IP_옵션이_있어도_헤더_길이를_보고_페이로드를_찾는다() { /* IHL > 5 */ }

@Test
void TCP_옵션이_있어도_데이터_오프셋을_보고_페이로드를_찾는다() { /* dataOffset > 5 */ }
```

- [ ] **Step 2: 실패 확인** — Run: `mvn -q -pl pcap test`

- [ ] **Step 3: 구현**

`record TcpSegment(Instant at, Endpoint... )` 대신 pcap 모듈은 `reconcile`에 의존하지 않으므로 자체 표현을 쓴다: `record TcpSegment(Instant at, String sourceAddress, int sourcePort, String targetAddress, int targetPort, long sequence, byte[] payload)`. IHL·dataOffset을 반드시 읽어 고정 20바이트를 가정하지 않는다.

- [ ] **Step 4: 통과 확인** — Expected: PASS (5개)

- [ ] **Step 5: 커밋**

```bash
git commit -am "feat: Ethernet/IPv4/TCP 디코드 — 헤더 길이를 읽어 고정 크기를 가정하지 않는다"
```

---

### Task 7: `TcpStreamAssembler`

**Files:**
- Create: `pcap/src/main/java/dev/krillin/huginn/pcap/TcpStream.java`
- Create: `pcap/src/main/java/dev/krillin/huginn/pcap/TcpStreamAssembler.java`
- Test: `pcap/src/test/java/dev/krillin/huginn/pcap/TcpStreamAssemblerTest.java`

- [ ] **Step 1: 실패하는 테스트 작성**

```java
@Test
void 순서대로_온_세그먼트를_이어붙인다() { /* seq 100, 103 → "abcdef" */ }

@Test
void 순서가_뒤바뀌어도_seq로_정렬한다() { /* 103 먼저, 100 나중 */ }

@Test
void 방향마다_별개_스트림이다() { /* A→B 와 B→A */ }

@Test
void 갭이_있으면_그_지점부터_UNDECIDABLE이다() {
    // seq 100(3바이트) 다음에 seq 200 — 사이가 비었다.
    // 조용히 이어붙이면 프레임 경계가 어긋나 엉뚱한 함수코드를 읽는다.
    TcpStream s = assemble(seg(100, "abc"), seg(200, "xyz"));
    assertTrue(s.hasGap());
    assertArrayEquals("abc".getBytes(), s.contiguousPrefix());
}

@Test
void 중복_세그먼트는_한_번만_반영한다() { /* 같은 seq 두 번 */ }
```

- [ ] **Step 2: 실패 확인**

- [ ] **Step 3: 구현**

완전한 TCP 스택을 만들지 않는다(설계 §5-③). 4-tuple + 방향을 키로 세그먼트를 모으고, seq 정렬 후 **첫 갭까지의 연속 구간**만 `contiguousPrefix()`로 내준다. 갭 이후는 버리고 `hasGap()`을 세운다.

- [ ] **Step 4: 통과 확인** — Expected: PASS (5개)

- [ ] **Step 5: 커밋**

```bash
git commit -am "feat: TCP 스트림 재조립 — 갭 이후는 UNDECIDABLE"
```

---

## Chunk 3: Modbus 해독과 배선

### Task 8: MBAP 프레이밍

**Files:**
- Create: `decode/src/main/java/dev/krillin/huginn/decode/ModbusFrame.java`
- Create: `decode/src/main/java/dev/krillin/huginn/decode/ModbusFramer.java`
- Test: `decode/src/test/java/dev/krillin/huginn/decode/ModbusFramerTest.java`

- [ ] **Step 1: 실패하는 테스트 작성**

MBAP: 트랜잭션ID(2) · 프로토콜ID(2, **반드시 0**) · 길이(2) · 유닛ID(1) · PDU.

```java
@Test
void 유효한_MBAP_프레임을_뽑는다() { /* ... */ }

@Test
void 한_스트림에_연속된_프레임_여러_개를_뽑는다() { /* 길이 필드로 경계를 찾는다 */ }

@Test
void protocolId가_0이_아니면_Modbus가_아니다() {
    // 포트가 502 여도 프레이밍이 아니면 Modbus 로 치지 않는다.
}

@Test
void 비표준_포트여도_프레이밍이_맞으면_Modbus로_인식한다() {
    // 우회하는 사람은 포트를 바꾼다. 포트는 힌트일 뿐이다 — 설계 §5-①.
}

@Test
void 길이_필드가_실제와_어긋나면_그_지점부터_해독을_멈춘다() { /* 남은 바이트는 미해독으로 보고 */ }
```

- [ ] **Step 2~4: 실패 확인 → 구현 → 통과 확인** — Expected: PASS (5개)

`ModbusFramer.frames(byte[] stream)`은 `record FramingResult(List<ModbusFrame> frames, int undecodedBytes)`를 돌려준다. 포트를 인자로 받지 않는다 — 프레이밍만으로 판정한다.

- [ ] **Step 5: 커밋**

```bash
git add decode/src decode/pom.xml
git commit -m "feat: MBAP 프레이밍 — 포트가 아니라 프레이밍으로 판정한다"
```

---

### Task 9: 함수코드 → `Access`

**Files:**
- Create: `decode/src/main/java/dev/krillin/huginn/decode/ModbusAccess.java`
- Test: `decode/src/test/java/dev/krillin/huginn/decode/ModbusAccessTest.java`

- [ ] **Step 1: 실패하는 테스트 작성**

```java
@ParameterizedTest @ValueSource(ints = {1, 2, 3, 4})
void 읽기_함수코드(int fc) { assertEquals(Access.READ, ModbusAccess.of(fc)); }

@ParameterizedTest @ValueSource(ints = {5, 6, 15, 16, 22, 23})
void 쓰기_함수코드(int fc) { assertEquals(Access.WRITE, ModbusAccess.of(fc)); }

@ParameterizedTest @ValueSource(ints = {8, 43})
void 제어_함수코드(int fc) { assertEquals(Access.CONTROL, ModbusAccess.of(fc)); }

@ParameterizedTest @ValueSource(ints = {0, 7, 99, 0x81})
void 모르는_함수코드는_UNDECIDABLE이다(int fc) {
    // 조용히 READ 로 치면 우회를 놓친다 — 설계 §5-④.
    assertEquals(Access.UNDECIDABLE, ModbusAccess.of(fc));
}
```

- [ ] **Step 2~4: 실패 확인 → 구현 → 통과 확인** — Expected: PASS (18개)

- [ ] **Step 5: 커밋**

```bash
git commit -am "feat: Modbus 함수코드 → Access, 모르는 코드는 UNDECIDABLE"
```

---

### Task 10: 파이프라인과 CLI

**Files:**
- Create: `decode/src/main/java/dev/krillin/huginn/decode/ModbusObserver.java`
- Create: `cli/src/main/java/dev/krillin/huginn/cli/Huginn.java`
- Create: `cli/src/main/java/dev/krillin/huginn/cli/Report.java`
- Test: `cli/src/test/java/dev/krillin/huginn/cli/EndToEndTest.java`

- [ ] **Step 1: 실패하는 테스트 작성**

```java
@Test
void 선언된_통신만_있는_캡처는_위반이_없다() { /* ... */ }

@Test
void 미등록_장비의_쓰기를_잡는다() {
    // 깨뜨렸을 때 잡히는지가 본 검증이다.
    // 정상 입력에서 0건인 것만으로는 아무것도 증명되지 않는다.
}

@Test
void 비표준_포트의_우회를_잡는다() { /* 502 가 아닌 포트로 같은 통신 */ }

@Test
void 리포트는_커버리지를_함께_낸다() {
    // "위반 0건" 과 "아무것도 못 읽었다" 를 구별할 수 없으면 이 도구는 위험하다 — 설계 §7.
    Report r = run(capture, policy);
    assertTrue(r.render().contains("처리 패킷"));
    assertTrue(r.render().contains("해독한 대화"));
    assertTrue(r.render().contains("UNDECIDABLE"));
}

@Test
void 같은_입력에_같은_리포트가_나온다() { /* 결정성 */ }
```

- [ ] **Step 2: 실패 확인**

- [ ] **Step 3: 구현**

`ModbusObserver`가 `TcpStream` → `List<Observation>`을 만든다. 갭이 있는 스트림은 연속 구간만 해독하고 나머지는 `UNDECIDABLE` 관찰 한 건으로 남긴다.

`Huginn.main(String[])`은 `huginn <capture.pcap> <policy.yaml>` 형태. 종료 코드는 Bifrost 게이트 관례를 따른다 — **0 = 위반 없음, 1 = 위반 있음, 2 = 사용법·입력 오류**.

`Report.render()` 최상단에 커버리지 세 줄을 낸다.

- [ ] **Step 4: 통과 확인** — Run: `mvn -q test` (전체)

- [ ] **Step 5: 커밋**

```bash
git add cli/src cli/pom.xml decode/src
git commit -m "feat: 파이프라인과 CLI — 리포트는 커버리지를 함께 낸다"
```

---

### Task 11: README와 실행 예시

**Files:**
- Create: `README.md`
- Create: `examples/policy.yaml`, `examples/README.md`
- Create: `LICENSE` (Apache-2.0, Bifrost에서 복사)

- [ ] **Step 1: README 작성**

Bifrost README의 톤을 따른다 — 무엇을 governance 하는지, 무엇을 하지 않는지, 그리고 **모든 주장에 대응하는 테스트**가 무엇인지.

핵심 문장: *"fail-closed는 길목을 지나는 것만 막는다. Huginn은 지나지 않은 것을 본다."*

- [ ] **Step 2: 공개 캡처 검증 스크립트**

`scripts/fetch-samples.sh` — 공개 ICS 캡처를 내려받고 SHA-256을 검증한다. **캡처 파일은 저장소에 넣지 않는다**(라이선스가 제각각).

- [ ] **Step 3: 커밋**

```bash
git add README.md LICENSE examples scripts
git commit -m "docs: README와 실행 예시"
```

---

## 완료 조건

- [ ] `mvn -q test` 전체 통과
- [ ] `decode` 밖의 어떤 클래스도 `Modbus`라는 이름을 모른다 — 2차에 S7comm을 붙일 때 이 경계가 시험받는다
- [ ] `pcap`·`decode`·`reconcile` 모듈에 런타임 외부 의존이 없다
- [ ] 리포트가 커버리지(처리 패킷·해독 대화·`UNDECIDABLE`)를 항상 낸다
- [ ] 위반이 든 합성 캡처에서 실제로 잡힌다 — 정상 캡처에서 0건인 것만으로는 증명되지 않는다
