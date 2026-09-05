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
