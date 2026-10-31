package dev.krillin.huginn.zeek;

import dev.krillin.huginn.reconcile.Access;
import dev.krillin.huginn.reconcile.Endpoint;
import dev.krillin.huginn.reconcile.Observation;
import dev.krillin.huginn.reconcile.Protocol;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;

import static dev.krillin.huginn.zeek.ZeekLogs.row;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ZeekObserverTest {

    private static ZeekObservationResult observe(String... texts) {
        List<ZeekLog> logs = new java.util.ArrayList<>();
        for (int i = 0; i < texts.length; i++) {
            logs.add(ZeekLogReader.parse(texts[i], "log" + i));
        }
        return ZeekObserver.observe(logs);
    }

    private static Observation only(ZeekObservationResult r) {
        assertEquals(1, r.observations().size(), r.observations().toString());
        return r.observations().get(0);
    }

    // ── s7comm ────────────────────────────────────────────────────────────────

    /** 연결은 PLC(10.0.0.2)가 열었고 이 패킷은 HMI(10.0.0.1)가 보냈다 — source_* 가 진짜 출발지다. */
    private static String s7(int rosctr, String fc, String fn, String sub) {
        return row("1700000000.250000", "C1", "10.0.0.2", 102, "10.0.0.1", 50000, "F",
            "10.0.0.1", 50000, "10.0.0.2", 102, rosctr, "x", 0, fc, fn, "-", sub, "-", "-");
    }

    @Test
    void S7_Job_은_요청이고_출발지는_source_열이다() {
        Observation o = only(observe(ZeekLogs.s7comm(s7(1, "0x05", "Write Variable", "-"))));

        assertEquals(new Endpoint("10.0.0.1", 50000), o.source(), "id.orig_* 가 아니라 source_* 다");
        assertEquals(new Endpoint("10.0.0.2", 102), o.target());
        assertEquals(Protocol.S7COMM, o.protocol());
        assertEquals(Access.WRITE, o.access());
        assertEquals("fc:5", o.objectRef(), "로그에 주소가 없으므로 지어내지 않는다");
        assertEquals(Instant.ofEpochSecond(1_700_000_000L, 250_000_000), o.at());
    }

    @Test
    void S7_제어는_decode_의_이름표를_쓰고_PLC_Control_은_서비스를_붙인다() {
        ZeekObservationResult r = observe(ZeekLogs.s7comm(
            s7(1, "0x29", "PLC Stop", "-"),
            s7(1, "0x28", "PLC Control", "PLC Start / Stop"),
            s7(1, "0x1d", "Start Upload", "-")));

        assertEquals(List.of("plc-stop", "plc-control (PLC Start / Stop)", "upload-start"),
            r.observations().stream().map(Observation::objectRef).toList());
        assertTrue(r.observations().stream().allMatch(o -> o.access() == Access.CONTROL));
    }

    @Test
    void S7_응답은_관찰하지_않는다() {
        ZeekObservationResult r = observe(ZeekLogs.s7comm(
            s7(2, "-", "-", "-"), s7(3, "0x04", "Read Variable", "-"), s7(7, "0x84", "Response", "Read SZL")));

        assertEquals(0, r.observations().size());
        assertEquals(3, r.byLog().get(0).responseRows());
    }

    @Test
    void S7_Userdata_요청은_UNDECIDABLE_로_남긴다() {
        Observation o = only(observe(ZeekLogs.s7comm(s7(7, "0x44", "Request: CPU Functions", "Read SZL"))));

        assertEquals(Access.UNDECIDABLE, o.access(), "pcap 경로가 Userdata 를 해석하지 않으므로 더 주장하지 않는다");
        assertEquals("userdata:Request: CPU Functions/Read SZL", o.objectRef());
    }

    @Test
    void S7_함수코드를_못_읽으면_UNDECIDABLE() {
        Observation o = only(observe(ZeekLogs.s7comm(s7(1, "-", "-", "-"))));
        assertEquals(Access.UNDECIDABLE, o.access());
        assertEquals("fc:-1", o.objectRef());
    }

    @Test
    void S7_방향을_모르는_행은_연결마다_UNDECIDABLE_하나() {
        ZeekObservationResult r = observe(ZeekLogs.s7comm(
            s7(9, "0x04", "x", "-"), s7(9, "0x04", "x", "-"), s7(7, "0x04", "x", "-")));

        Observation o = only(r);
        assertEquals(Access.UNDECIDABLE, o.access());
        assertEquals("-", o.objectRef());
        assertEquals(3, r.byLog().get(0).unresolvedRows());
    }

    // ── s7comm_plus ───────────────────────────────────────────────────────────

    private static String plus(String opcode, String fc, String fn) {
        return row("1700000001.000000", "C2", "10.0.0.3", 49154, "10.0.0.4", 102, "T",
            "10.0.0.3", 49154, "10.0.0.4", 102, 3, opcode, "x", fc, fn);
    }

    @Test
    void S7plus_요청만_관찰하고_다른_프로토콜_이름을_쓴다() {
        ZeekObservationResult r = observe(ZeekLogs.s7commPlus(
            plus("0x31", "0x04f2", "Set Variable"),
            plus("0x31", "0x054c", "Get Multi Variables"),
            plus("0x31", "0x04ca", "Create Object"),
            plus("0x32", "0x04f2", "Set Variable"),
            plus("0x33", "-", "-")));

        assertEquals(List.of(Access.WRITE, Access.READ, Access.UNDECIDABLE),
            r.observations().stream().map(Observation::access).toList());
        assertTrue(r.observations().stream().allMatch(o -> o.protocol() == Protocol.S7COMM_PLUS));
        assertEquals("fn:Set Variable", r.observations().get(0).objectRef());
        LogCoverage c = r.byLog().get(0);
        assertEquals(5, c.rows());
        assertEquals(3, c.requestRows());
        assertEquals(2, c.responseRows(), "응답과 알림");
    }

    // ── modbus_detailed ───────────────────────────────────────────────────────

    /** 열: tid unit func address quantity request_values matched request_data exception_code mei_type */
    private static String mb(String uid, int tid, String func, String address, String quantity,
                             String requestValues, String matched, String exception, String mei) {
        return row("1700000002.000000", uid, "10.0.1.20", 40000, "10.0.2.11", 502, tid, 1, func,
            address, quantity, requestValues, "-", "-", matched, "-", "-", "-", "-", exception, mei);
    }

    @Test
    void Modbus_짝지은_트랜잭션은_요청이고_주소는_pcap_경로와_같은_표기다() {
        Observation o = only(observe(ZeekLogs.modbus(
            mb("C3", 1, "WRITE_SINGLE_REGISTER", "0", "-", "7", "T", "-", "-"))));

        assertEquals(new Endpoint("10.0.1.20", 40000), o.source());
        assertEquals(Access.WRITE, o.access());
        assertEquals("holding:40001", o.objectRef());
    }

    @Test
    void Modbus_예외로_끝난_짝도_요청을_본_것이다() {
        Observation o = only(observe(ZeekLogs.modbus(
            mb("C3", 1, "WRITE_MULTIPLE_COILS", "16", "8", "-", "T", "ILLEGAL_FUNCTION", "-"))));
        assertEquals(Access.WRITE, o.access());
        assertEquals("coil:17", o.objectRef());
    }

    @Test
    void Modbus_짝_없는_요청은_요청_열이_있으면_관찰한다() {
        ZeekObservationResult r = observe(ZeekLogs.modbus(
            mb("C3", 1, "READ_COILS", "0", "8", "-", "F", "-", "-"),
            mb("C3", 2, "READ_COILS", "-", "-", "-", "F", "-", "-")));

        assertEquals(List.of(Access.READ, Access.UNDECIDABLE),
            r.observations().stream().map(Observation::access).toList());
        assertEquals(1, r.byLog().get(0).unresolvedRows(), "응답만 남은 행");
    }

    @Test
    void Modbus_짝_없는_예외_응답은_연결마다_UNDECIDABLE_하나() {
        ZeekObservationResult r = observe(ZeekLogs.modbus(
            mb("C3", 1, "READ_WRITE_MULTIPLE_REGISTERS_EXCEPTION", "-", "-", "-", "-", "ILLEGAL_FUNCTION", "-"),
            mb("C3", 2, "READ_WRITE_MULTIPLE_REGISTERS_EXCEPTION", "-", "-", "-", "-", "ILLEGAL_FUNCTION", "-"),
            mb("C4", 1, "READ_WRITE_MULTIPLE_REGISTERS_EXCEPTION", "-", "-", "-", "-", "ILLEGAL_FUNCTION", "-")));

        assertEquals(2, r.observations().size(), "C3 하나, C4 하나");
        assertTrue(r.observations().stream().allMatch(o -> o.access() == Access.UNDECIDABLE));
        assertEquals(3, r.byLog().get(0).unresolvedRows());
    }

    @Test
    void Modbus_헤더만_쓰는_함수는_연속한_두_행이_한_요청이다() {
        ZeekObservationResult r = observe(ZeekLogs.modbus(
            mb("C3", 5, "REPORT_SLAVE_ID", "-", "-", "-", "-", "-", "-"),
            mb("C3", 5, "REPORT_SLAVE_ID", "-", "-", "-", "-", "-", "-"),
            mb("C3", 6, "READ_EXCEPTION_STATUS", "-", "-", "-", "-", "-", "-")));

        assertEquals(List.of("fc:17", "-"), r.observations().stream().map(Observation::objectRef).toList());
        assertEquals(List.of(Access.READ, Access.UNDECIDABLE),
            r.observations().stream().map(Observation::access).toList(), "짝 없는 한 행은 방향을 모른다");
        LogCoverage c = r.byLog().get(0);
        assertEquals(2, c.requestRows());
        assertEquals(1, c.unresolvedRows());
    }

    @Test
    void Modbus_tid_나_함수가_다른_두_행은_짝이_아니다() {
        ZeekObservationResult r = observe(ZeekLogs.modbus(
            mb("C3", 7, "REPORT_SLAVE_ID", "-", "-", "-", "-", "-", "-"),
            mb("C3", 8, "REPORT_SLAVE_ID", "-", "-", "-", "-", "-", "-"),
            mb("C3", 8, "READ_EXCEPTION_STATUS", "-", "-", "-", "-", "-", "-")));

        assertEquals(List.of(Access.UNDECIDABLE), r.observations().stream().map(Observation::access).toList());
        assertEquals(3, r.byLog().get(0).unresolvedRows());
    }

    @Test
    void Modbus_tid_를_재사용해도_두_행씩_끊어_센다() {
        ZeekObservationResult r = observe(ZeekLogs.modbus(
            mb("C3", 0, "REPORT_SLAVE_ID", "-", "-", "-", "-", "-", "-"),
            mb("C3", 0, "REPORT_SLAVE_ID", "-", "-", "-", "-", "-", "-"),
            mb("C3", 0, "REPORT_SLAVE_ID", "-", "-", "-", "-", "-", "-"),
            mb("C3", 0, "REPORT_SLAVE_ID", "-", "-", "-", "-", "-", "-")));
        assertEquals(2, r.observations().size());
    }

    @Test
    void Modbus_FC43_은_MEI_14_가_정확할_때만_읽기다() {
        ZeekObservationResult r = observe(ZeekLogs.modbus(
            mb("C3", 1, "ENCAP_INTERFACE_TRANSPORT", "-", "-", "-", "T", "-", "Read Device Identification"),
            mb("C3", 2, "ENCAP_INTERFACE_TRANSPORT", "-", "-", "-", "T", "-", "CANopen"),
            mb("C3", 3, "ENCAP_INTERFACE_TRANSPORT", "-", "-", "-", "T", "-",
                "Read Device Identification and CANopen")));

        assertEquals(List.of(Access.READ, Access.UNDECIDABLE, Access.UNDECIDABLE),
            r.observations().stream().map(Observation::access).toList());
        assertEquals("fc:43", r.observations().get(0).objectRef(), "Read Device ID 코드는 이 로그에 없다");
    }

    @Test
    void Modbus_진단은_통째로_CONTROL_이다() {
        assertEquals(Access.CONTROL, only(observe(ZeekLogs.modbus(
            mb("C3", 1, "DIAGNOSTICS", "-", "-", "-", "T", "-", "-")))).access());
    }

    @Test
    void Modbus_모르는_함수는_UNDECIDABLE_이고_이름을_남긴다() {
        ZeekObservationResult r = observe(ZeekLogs.modbus(
            mb("C3", 1, "SOMETHING_NEW", "-", "-", "-", "T", "-", "-"),
            mb("C3", 2, "unknown-100", "-", "-", "-", "T", "-", "-")));

        assertEquals(List.of("func:SOMETHING_NEW", "fc:100"),
            r.observations().stream().map(Observation::objectRef).toList());
        assertTrue(r.observations().stream().allMatch(o -> o.access() == Access.UNDECIDABLE));
    }

    @Test
    void Modbus_이름표는_Zeek_의_함수코드와_같다() {
        assertEquals(0x17, ZeekObserver.ModbusNames.code("READ_WRITE_MULTIPLE_REGISTERS"));
        assertEquals(0x0F, ZeekObserver.ModbusNames.code("WRITE_MULTIPLE_COILS_EXCEPTION"));
        assertEquals(0x2B, ZeekObserver.ModbusNames.code("ENCAP_INTERFACE_TRANSPORT"));
        assertEquals(-1, ZeekObserver.ModbusNames.code(null));
    }

    // ── 공통 ─────────────────────────────────────────────────────────────────

    @Test
    void 가린_시각은_거부한다() {
        String masked = ZeekLogs.s7comm(s7(1, "0x04", "Read Variable", "-")
            .replace("1700000000.250000", "XXXXXXXXXX.XXXXXX"));
        String message = assertThrows(ZeekLogException.class, () -> observe(masked)).getMessage();
        assertTrue(message.contains("ts"), message);
    }

    @Test
    void 출발지가_비면_거부한다() {
        String noHost = ZeekLogs.s7comm(s7(1, "0x04", "Read Variable", "-").replace("\t10.0.0.1\t50000\t10.0.0.2", "\t-\t50000\t10.0.0.2"));
        assertThrows(ZeekLogException.class, () -> observe(noHost));
    }

    @Test
    void 행은_요청_응답_미확정_중_하나로_빠짐없이_간다() {
        ZeekObservationResult r = observe(
            ZeekLogs.icsnpp("s7comm-snap7/s7comm.log"),
            ZeekLogs.icsnpp("s7comm-plus/s7comm_plus.log"),
            ZeekLogs.icsnpp("modbus-basic/modbus_detailed.log"));
        for (LogCoverage c : r.byLog()) {
            assertEquals(c.rows(), c.requestRows() + c.responseRows() + c.unresolvedRows(), c.toString());
        }
    }

    @Test
    void 관찰_순서는_파일_순서다() {
        ZeekObservationResult r = observe(
            ZeekLogs.s7commPlus(plus("0x31", "0x04f2", "Set Variable")),
            ZeekLogs.s7comm(s7(1, "0x04", "Read Variable", "-")));
        assertEquals(List.of(Protocol.S7COMM_PLUS, Protocol.S7COMM),
            r.observations().stream().map(Observation::protocol).toList());
    }

    @Test
    void 십육진_함수코드() {
        assertEquals(0x04F2, ZeekObserver.hex("0x04f2"));
        assertEquals(-1, ZeekObserver.hex("04f2"));
        assertEquals(-1, ZeekObserver.hex(null));
    }
}
