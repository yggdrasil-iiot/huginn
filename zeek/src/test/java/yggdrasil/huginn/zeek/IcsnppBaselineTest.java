package yggdrasil.huginn.zeek;

import yggdrasil.huginn.reconcile.Observation;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * ICSNPP 자체 시험의 기준 로그(원본 그대로 커밋, {@code src/test/resources/icsnpp/README.md})를
 * 읽는다. 수치는 그 로그를 직접 세어 확인한 값이다.
 *
 * <p>기준 로그는 Zeek 9.0.1 + 고정 커밋의 ICSNPP 로 트레이스를 다시 돌린 출력과 {@code ts}·{@code uid}·
 * 임의 링크 id 를 빼고 같다(2026-11-01 확인). 그래서 이 시험은 실제 Zeek 출력을 읽는 시험이기도 하다.
 */
class IcsnppBaselineTest {

    private static Map<String, Long> tally(ZeekObservationResult r) {
        return r.observations().stream().collect(Collectors.groupingBy(
            o -> o.protocol() + " " + o.access(), TreeMap::new, Collectors.counting()));
    }

    private static ZeekObservationResult observe(String... resources) {
        return ZeekObserver.observe(java.util.Arrays.stream(resources)
            .map(r -> ZeekLogReader.parse(ZeekLogs.icsnpp(r), r)).toList());
    }

    @Test
    void 열_구성은_맞춰_짠_그대로다() {
        // ICSNPP 는 릴리스가 없다. 이 줄이 바뀌면 열 의미가 바뀌었는지 먼저 확인한다.
        assertEquals("#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tis_orig\tsource_h\tsource_p"
                + "\tdestination_h\tdestination_p\trosctr_code\trosctr_name\tpdu_reference\tfunction_code"
                + "\tfunction_name\tsubfunction_code\tsubfunction_name\terror_class\terror_code",
            fieldsLine("s7comm-snap7/s7comm.log"));
        assertEquals("#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tis_orig\tsource_h\tsource_p"
                + "\tdestination_h\tdestination_p\tversion\topcode\topcode_name\tfunction_code\tfunction_name",
            fieldsLine("s7comm-plus/s7comm_plus.log"));
        assertEquals("#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\ttid\tunit\tfunc\taddress"
                + "\tquantity\trequest_values\tresponse_values\tmodbus_detailed_link_id\tmatched"
                + "\trequest_subfunction_code\tresponse_subfunction_code\trequest_data\tresponse_data"
                + "\texception_code\tmei_type",
            fieldsLine("modbus-basic/modbus_detailed.log"));
    }

    private static String fieldsLine(String resource) {
        return ZeekLogs.icsnppRaw(resource).lines().filter(l -> l.startsWith("#fields")).findFirst().orElseThrow();
    }

    @Test
    void snap7_S7comm() {
        ZeekObservationResult r = observe("s7comm-snap7/s7comm.log");

        // Job 31 = Read 2 · Write 2 · 제어 17(PLC Control 3 · PLC Stop 1 · Upload 계열 13) ·
        // Setup Communication 1 · Userdata 요청 9 는 UNDECIDABLE.
        assertEquals(Map.of("S7COMM CONTROL", 17L, "S7COMM READ", 2L, "S7COMM UNDECIDABLE", 10L,
            "S7COMM WRITE", 2L), tally(r));
        LogCoverage c = r.byLog().get(0);
        assertEquals(62, c.rows());
        assertEquals(31, c.requestRows());
        assertEquals(31, c.responseRows());
        assertEquals(0, c.unresolvedRows());
    }

    @Test
    void s7comm_plus_트레이스는_두_프로토콜을_싣는다() {
        ZeekObservationResult r = observe("s7comm-plus/s7comm.log", "s7comm-plus/s7comm_plus.log");

        // S7comm-plus 요청 34 = Set Variable 26 · Set Multi Variables 2(WRITE) · Get Multi Variables 6(READ).
        // 응답·알림 87 은 관찰하지 않는다. 같은 캡처에 고전 S7comm 도 섞여 있다.
        assertEquals(Map.of("S7COMM READ", 8L, "S7COMM UNDECIDABLE", 1L, "S7COMM WRITE", 8L,
            "S7COMM_PLUS READ", 6L, "S7COMM_PLUS WRITE", 28L), tally(r));
        LogCoverage plus = r.byLog().get(1);
        assertEquals(121, plus.rows());
        assertEquals(34, plus.requestRows());
        assertEquals(87, plus.responseRows());
    }

    @Test
    void modbus_basic() {
        ZeekObservationResult r = observe("modbus-basic/modbus_detailed.log");

        // 26 행 = 짝지은 트랜잭션 22 + 헤더만 쓰는 함수 두 쌍(FC 7·17). 관찰 24 —
        // READ 14(FC 1·2·4 각 2, FC 3 셋, FC 7·17·20·24·43 각 1) ·
        // WRITE 9(FC 22·23 각 2, FC 5·6·15·16·21 각 1) · CONTROL 1(FC 8).
        assertEquals(Map.of("MODBUS_TCP CONTROL", 1L, "MODBUS_TCP READ", 14L, "MODBUS_TCP WRITE", 9L), tally(r));
        assertEquals(List.of("coil:2", "coil:2", "discrete:10002", "discrete:10002"),
            r.observations().stream().map(Observation::objectRef)
                .filter(ref -> ref.startsWith("coil") || ref.startsWith("discrete")).toList().subList(0, 4)
                .stream().sorted().toList());
        LogCoverage c = r.byLog().get(0);
        assertEquals(26, c.rows());
        assertEquals(26, c.requestRows());
    }
}
