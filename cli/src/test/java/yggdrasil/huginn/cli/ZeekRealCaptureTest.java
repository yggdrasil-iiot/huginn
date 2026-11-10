package yggdrasil.huginn.cli;

import yggdrasil.huginn.reconcile.Protocol;
import yggdrasil.huginn.reconcile.Severity;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * 4SICS 세 캡처를 Zeek 9.0.1 + ICSNPP(고정 커밋)로 돌린 로그를 같은 정책으로 대사한다.
 * 로그는 {@code scripts/zeek-logs.sh} 로 만들고, 캡처와 같은 이유로 커밋하지 않는다.
 * {@code HUGINN_ZEEK_SAMPLES} 가 {@code samples/zeek} 를 가리킬 때만 돈다.
 *
 * <p>pcap 경로의 결과는 {@code samples/README.md} 에 있다. 두 경로의 차이는 <b>로그에 무엇이
 * 남았는가</b>의 차이다 — 이 시험의 수는 로그 경로의 기준선이고, 차이의 원인은
 * {@code samples/README.md} 에 적는다.
 */
@EnabledIfEnvironmentVariable(named = "HUGINN_ZEEK_SAMPLES", matches = ".+")
class ZeekRealCaptureTest {

    private static ZeekReport run(String capture) throws Exception {
        Path dir = Path.of(System.getenv("HUGINN_ZEEK_SAMPLES"), capture);
        Map<String, String> logs = new LinkedHashMap<>();
        for (String name : new String[]{"s7comm.log", "modbus_detailed.log"}) {
            Path log = dir.resolve(name);
            if (Files.exists(log)) {
                logs.put(log.toString(), Files.readString(log, StandardCharsets.UTF_8));
            }
        }
        String policy = Files.readString(dir.getParent().getParent().resolve(capture + "-policy.yaml"),
            StandardCharsets.UTF_8);
        return Pipeline.runZeek(logs, policy);
    }

    private static long count(ZeekReport r, Protocol protocol, Severity severity) {
        return r.findings().stream()
            .filter(f -> f.evidence().protocol() == protocol && f.severity() == severity).count();
    }

    @Test
    void 캡처_151020() throws Exception {
        ZeekReport r = run("4SICS-GeekLounge-151020");

        assertEquals(2_547, r.byLog().get(0).requestRows());
        // pcap 경로는 23 이다. 갭 이후 구간을 읽기 전의 pcap 경로가 냈던 18 과 같다.
        assertEquals(18, r.findings().size());
        assertEquals(18, count(r, Protocol.S7COMM, Severity.HIGH));
    }

    @Test
    void 캡처_151021() throws Exception {
        ZeekReport r = run("4SICS-GeekLounge-151021");

        assertEquals(68, r.findings().size());
        assertEquals(48, count(r, Protocol.S7COMM, Severity.HIGH));
        assertEquals(14, count(r, Protocol.S7COMM, Severity.MEDIUM));
        // pcap 경로는 장비 열거 스캔 11 건을 전부 READ 로 본다. 로그에서는 5 건이 짝 없는 FC 43 이라
        // 요청인지 응답인지 정할 수 없다 — 연결마다 UNDECIDABLE 하나로 남는다.
        assertEquals(6, count(r, Protocol.MODBUS_TCP, Severity.MEDIUM));
        assertEquals(23, r.undecidableObservations());
    }

    @Test
    void 캡처_151022() throws Exception {
        ZeekReport r = run("4SICS-GeekLounge-151022");

        assertEquals(5_330, r.findings().size());
        assertEquals(14, count(r, Protocol.S7COMM, Severity.HIGH));
        assertEquals(7, count(r, Protocol.S7COMM, Severity.MEDIUM));
        assertEquals(5_272, count(r, Protocol.MODBUS_TCP, Severity.HIGH));
        assertEquals(37, count(r, Protocol.MODBUS_TCP, Severity.MEDIUM));
        // 짝 없는 예외 응답 등 방향을 정할 수 없는 Modbus 행 — 관찰을 지어내지 않는다.
        assertEquals(19_454, r.byLog().get(1).unresolvedRows());
        assertEquals(120, r.undecidableObservations());
    }
}
