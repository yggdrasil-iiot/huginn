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
