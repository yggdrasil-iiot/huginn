package yggdrasil.huginn.cli;

import yggdrasil.huginn.reconcile.Finding;
import yggdrasil.huginn.reconcile.Protocol;
import yggdrasil.huginn.reconcile.Severity;
import yggdrasil.huginn.zeek.ZeekLogs;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Zeek 로그에서 리포트·종료 코드까지. 입력은 ICSNPP 기준 로그다 — 실제 Zeek 이 낸 출력이라
 * 손으로 만든 로그보다 형식을 덜 가정한다. 그 트레이스는 고전 S7comm(192.168.0.33)과
 * S7comm-plus(192.168.0.3)를 함께 싣는다.
 */
class ZeekEndToEndTest {

    private static final String PEERS = """
        version: 1
        peers:
          - id: hmi-a
            address: 192.168.0.33
          - id: hmi-b
            address: 192.168.0.3
          - id: plc
            address: 192.168.0.1
        allowed:
          - from: hmi-a
            to: plc
            protocol: S7COMM
            access: [READ, WRITE]
        """;

    private static final String BOTH_DECLARED = PEERS + """
          - from: hmi-b
            to: plc
            protocol: S7COMM_PLUS
            access: [READ, WRITE]
        """;

    /** S7comm-plus 쪽을 S7COMM 으로 선언했다 — 이름이 다르므로 아무것도 허용하지 않는다. */
    private static final String PLUS_AS_S7COMM = PEERS + """
          - from: hmi-b
            to: plc
            protocol: S7COMM
            access: [READ, WRITE]
        """;

    private static Map<String, String> plusTrace() {
        Map<String, String> logs = new LinkedHashMap<>();
        logs.put("s7comm.log", ZeekLogs.icsnpp("s7comm-plus/s7comm.log"));
        logs.put("s7comm_plus.log", ZeekLogs.icsnpp("s7comm-plus/s7comm_plus.log"));
        return logs;
    }

    @Test
    void 두_프로토콜을_모두_선언하면_위반이_없다() {
        ZeekReport report = Pipeline.runZeek(plusTrace(), BOTH_DECLARED);

        assertTrue(report.findings().isEmpty(), report.render());
        assertEquals(1, report.undecidableObservations(), "S7comm Setup Communication 하나");
    }

    @Test
    void S7COMM_선언은_S7comm_plus_를_덮지_않는다() {
        ZeekReport report = Pipeline.runZeek(plusTrace(), PLUS_AS_S7COMM);

        assertEquals(34, report.findings().size());
        assertTrue(report.findings().stream().allMatch(f -> f.evidence().protocol() == Protocol.S7COMM_PLUS));
        assertEquals(28, report.findings().stream().filter(f -> f.severity() == Severity.HIGH).count(),
            "Set Variable 26 · Set Multi Variables 2");
        Finding first = report.findings().get(0);
        assertEquals("192.168.0.3", first.evidence().source().address());
        assertEquals("fn:Set Variable", first.evidence().objectRef());
    }

    @Test
    void 리포트는_행의_행방을_내고_패킷_커버리지는_없다고_말한다() {
        String out = Pipeline.runZeek(plusTrace(), BOTH_DECLARED).render();

        assertTrue(out.contains("(Zeek 로그)"));
        assertTrue(out.contains("응답·알림 행"));
        assertTrue(out.contains("방향 미확정 행"));
        assertTrue(out.contains("패킷·바이트 커버리지 없음"));
        assertTrue(out.contains("s7comm_plus      S7COMM_PLUS         121         34         87          0         34           0"),
            out);
        assertTrue(out.endsWith("\n위반 없음\n"));
    }

    @Test
    void 같은_입력에_같은_리포트가_나온다() {
        assertEquals(Pipeline.runZeek(plusTrace(), PLUS_AS_S7COMM).render(),
            Pipeline.runZeek(plusTrace(), PLUS_AS_S7COMM).render());
    }

    // ── 명령줄 ─────────────────────────────────────────────────────────────────

    private static Path write(Path dir, String name, String text) throws IOException {
        Path path = dir.resolve(name);
        Files.writeString(path, text, StandardCharsets.UTF_8);
        return path;
    }

    @Test
    void 종료코드_0과_1(@TempDir Path dir) throws IOException {
        Path s7 = write(dir, "s7comm.log", ZeekLogs.icsnpp("s7comm-plus/s7comm.log"));
        Path plus = write(dir, "s7comm_plus.log", ZeekLogs.icsnpp("s7comm-plus/s7comm_plus.log"));

        assertEquals(0, Huginn.run(new String[]{"--zeek-log", s7.toString(), "--zeek-log", plus.toString(),
            write(dir, "ok.yaml", BOTH_DECLARED).toString()}));
        assertEquals(1, Huginn.run(new String[]{"--zeek-log", s7.toString(), "--zeek-log", plus.toString(),
            write(dir, "bad.yaml", PLUS_AS_S7COMM).toString()}));
    }

    @Test
    void 같은_파일을_두_번_주면_종료코드_2다(@TempDir Path dir) throws IOException {
        // 같은 요청을 두 번 세면 위반 수가 부풀고, 그 수로 무엇을 조치할지 정하게 된다.
        Path s7 = write(dir, "s7comm.log", ZeekLogs.icsnpp("s7comm-plus/s7comm.log"));
        Path policy = write(dir, "p.yaml", BOTH_DECLARED);

        assertEquals(2, Huginn.run(new String[]{"--zeek-log", s7.toString(),
            "--zeek-log", dir.resolve(".").resolve("s7comm.log").toString(), policy.toString()}));
    }

    @Test
    void 사용법이_틀리면_종료코드_2다(@TempDir Path dir) throws IOException {
        Path s7 = write(dir, "s7comm.log", ZeekLogs.icsnpp("s7comm-plus/s7comm.log"));
        Path policy = write(dir, "p.yaml", BOTH_DECLARED);

        assertEquals(2, Huginn.run(new String[]{"--zeek-log", policy.toString()}), "로그가 없다");
        assertEquals(2, Huginn.run(new String[]{"--zeek-log", s7.toString(), s7.toString(), policy.toString()}),
            "--zeek-log 없이 준 파일");
        Path plus = write(dir, "s7comm_plus.log", ZeekLogs.icsnpp("s7comm-plus/s7comm_plus.log"));
        assertEquals(2, Huginn.run(new String[]{"--zeek-log", s7.toString(), "--zeek", plus.toString(),
            policy.toString()}), "모르는 플래그 — 둘 다 읽을 수 있는 로그여도 거부한다");
        assertEquals(2, Huginn.run(new String[]{"--zeek-log", s7.toString(), "--zeek-log", policy.toString()}),
            "정책이 없다 — 정책 YAML 을 로그로 읽으려다 실패한다");
    }

    @Test
    void 읽지_않는_로그는_종료코드_2다(@TempDir Path dir) throws IOException {
        Path conn = write(dir, "conn.log", ZeekLogs.icsnpp("s7comm-plus/s7comm.log").replace("#path\ts7comm", "#path\tconn"));
        Path policy = write(dir, "p.yaml", BOTH_DECLARED);

        assertEquals(2, Huginn.run(new String[]{"--zeek-log", conn.toString(), policy.toString()}));
    }
}
