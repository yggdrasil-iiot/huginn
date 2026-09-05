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
