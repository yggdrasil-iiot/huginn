package dev.krillin.huginn.cli;

import dev.krillin.huginn.decode.ModbusFixtures;
import dev.krillin.huginn.pcap.PcapBuilder;
import dev.krillin.huginn.reconcile.Access;
import dev.krillin.huginn.reconcile.Finding;
import dev.krillin.huginn.reconcile.Severity;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;


import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * pcap 바이트에서 리포트까지 실제로 도는 경로. 픽스처는 pcap·decode 의 test-jar 에서 그대로
 * 당겨 쓴다 — 여기서 다시 짜면 조립기가 두 벌로 갈라진다.
 */
class EndToEndTest {

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

    /** FC 3 읽기 요청(4바이트 PDU → REQUEST_ONLY). */
    private static final byte[] READ_REQUEST = ModbusFixtures.mbap(1, 1, 3, ModbusFixtures.pdu(0, 2));
    /** FC 3 읽기 응답(바이트수 4 → RESPONSE_ONLY). */
    private static final byte[] READ_RESPONSE = ModbusFixtures.mbap(1, 1, 3, new byte[]{4, 0, 0, 0, 0});
    /** FC 16 다중 쓰기 요청(9바이트 → REQUEST_ONLY). */
    private static final byte[] WRITE_REQUEST =
        ModbusFixtures.mbap(2, 1, 16, new byte[]{0, 0, 0, 2, 4, 0, 1, 0, 2});
    /** FC 16 다중 쓰기 응답(정확히 4바이트 → RESPONSE_ONLY). */
    private static final byte[] WRITE_RESPONSE = ModbusFixtures.mbap(2, 1, 16, new byte[]{0, 0, 0, 2});

    private static byte[] frame(String src, int sport, String dst, int dport, byte[] payload) {
        return PcapBuilder.ethernetIpv4Tcp(src, sport, dst, dport, 1000, PcapBuilder.FLAG_ACK,
            payload, 0, 0, 0);
    }

    private static byte[] capture(byte[]... frames) {
        PcapBuilder builder = PcapBuilder.ethernet();
        for (int i = 0; i < frames.length; i++) {
            builder.packet(1_700_000_000 + i, 0, frames[i]);
        }
        return builder.build();
    }

    /** 선언된 폴링 한 왕복 — hmi:40000 → plc:502 읽기. */
    private static byte[] declaredReadCapture() {
        return capture(
            frame("10.0.1.20", 40000, "10.0.2.11", 502, READ_REQUEST),
            frame("10.0.2.11", 502, "10.0.1.20", 40000, READ_RESPONSE));
    }

    @Test
    void 선언된_통신만_있는_캡처는_위반이_없다() {
        // 요청과 응답을 모두 넣는다 — 응답을 빼면 요청/응답 결함을 은폐하는 테스트가 된다.
        Report report = Pipeline.run(declaredReadCapture(), POLICY);

        assertTrue(report.findings().isEmpty());
        assertEquals(1, report.decodedConversations());
    }

    @Test
    void 미등록_장비의_쓰기를_잡는다() {
        // 깨뜨렸을 때 잡히는지가 본 검증이다. 정상 입력에서 0건인 것만으로는 증명되지 않는다.
        Report report = Pipeline.run(capture(
            frame("10.0.9.99", 40000, "10.0.2.11", 502, WRITE_REQUEST),
            frame("10.0.2.11", 502, "10.0.9.99", 40000, WRITE_RESPONSE)), POLICY);

        assertEquals(1, report.findings().size());
        Finding finding = report.findings().get(0);
        assertEquals(Severity.HIGH, finding.severity());
        assertEquals(Access.WRITE, finding.evidence().access());
        assertEquals("10.0.9.99", finding.evidence().source().address());
    }

    @Test
    void 비표준_포트의_우회를_잡는다() {
        // 서버 50502 / 클라 1288 — 포트 신호는 거울상이라 아무것도 말해주지 않는다.
        // 9바이트 요청 / 4바이트 응답이라는 PDU 형태만이 방향을 가른다.
        Report report = Pipeline.run(capture(
            frame("10.0.9.99", 1288, "10.0.2.11", 50502, WRITE_REQUEST),
            frame("10.0.2.11", 50502, "10.0.9.99", 1288, WRITE_RESPONSE)), POLICY);

        assertEquals(1, report.findings().size());
        assertEquals(Severity.HIGH, report.findings().get(0).severity());
        assertEquals("10.0.9.99", report.findings().get(0).evidence().source().address());
    }

    @Test
    void 포트가_502여도_프레이밍이_아니면_Modbus로_치지_않는다() {
        // §5-① 을 양방향으로 고정한다 — 502 에 실린 SSH 는 대상 외이고,
        // 9999 에 실린 MBAP 는 해독한다. 어느 쪽도 포트가 근거가 아니다.
        byte[] ssh = "SSH-2.0-OpenSSH_9.0\r\n".getBytes(StandardCharsets.US_ASCII);
        Report report = Pipeline.run(capture(
            frame("10.0.1.20", 40000, "10.0.2.11", 502, ssh),
            frame("10.0.1.20", 41000, "10.0.2.11", 9999, READ_REQUEST),
            frame("10.0.2.11", 9999, "10.0.1.20", 41000, READ_RESPONSE)), POLICY);

        assertEquals(1, report.skippedConversations(), "502 의 SSH 는 대상 외다");
        assertEquals(1, report.decodedConversations(), "9999 의 MBAP 는 해독한다");
        assertTrue(report.findings().isEmpty(), "9999 의 읽기도 선언된 hmi→plc 라 위반이 아니다");
    }

    @Test
    void 리포트는_커버리지를_함께_낸다() {
        Report r = Pipeline.run(declaredReadCapture(), POLICY);
        String out = r.render();
        assertTrue(out.contains("처리 패킷"));
        assertTrue(out.contains("대상 외 패킷"));
        assertTrue(out.contains("해독한 대화"));
        assertTrue(out.contains("대상 외 대화"));
        assertTrue(out.contains("UNDECIDABLE 대화"));
        assertTrue(out.contains("UNDECIDABLE 관찰"), "대화 수와 관찰 수는 다른 값이며 둘 다 내야 한다");
    }

    @Test
    void 리포트는_못_본_바이트를_비율과_함께_낸다() {
        // 이 줄이 없으면 "해독한 대화 2" 가 그 대화의 대부분을 못 봤다는 사실을 숨긴다.
        String out = Pipeline.run(declaredReadCapture(), POLICY).render();

        assertTrue(out.contains("미관측 바이트"));
        String line = out.lines().filter(l -> l.contains("미관측 바이트")).findFirst().orElseThrow();
        assertTrue(line.matches(".*\\d+\\.\\d%\\).*"),
            "비율은 소수 한 자리다: " + line);
    }

    @Test
    void 비산업_트래픽은_UNDECIDABLE이_아니라_대상_외로_센다() {
        // 이 구분이 없으면 커버리지 지표가 캡처의 SSH·HTTP 양에 지배된다.
        byte[] ssh = "SSH-2.0-OpenSSH_9.0\r\n".getBytes(StandardCharsets.US_ASCII);
        Report report = Pipeline.run(capture(
            frame("10.0.1.20", 40000, "10.0.2.11", 502, READ_REQUEST),
            frame("10.0.2.11", 502, "10.0.1.20", 40000, READ_RESPONSE),
            frame("10.0.1.20", 40002, "10.0.3.5", 22, ssh)), POLICY);

        assertEquals(1, report.skippedConversations());
        assertEquals(0, report.undecidableConversations());
        assertEquals(1, report.decodedConversations());
    }

    @Test
    void 계약이_잘못되면_종료코드_2다(@TempDir Path dir) throws IOException {
        // 위반 1 과 구별된다 — 계약을 못 읽은 것과 위반을 찾은 것은 다른 사건이다.
        Path pcap = write(dir, "capture.pcap", declaredReadCapture());
        Path policy = write(dir, "policy.yaml", "version: 99\npeers: []\nallowed: []\n");

        assertEquals(2, Huginn.run(new String[]{pcap.toString(), policy.toString()}));
    }

    @Test
    void 위반이_없으면_종료코드_0이다(@TempDir Path dir) throws IOException {
        Path pcap = write(dir, "capture.pcap", declaredReadCapture());
        Path policy = write(dir, "policy.yaml", POLICY);

        assertEquals(0, Huginn.run(new String[]{pcap.toString(), policy.toString()}));
    }

    @Test
    void 위반이_있으면_종료코드_1이다(@TempDir Path dir) throws IOException {
        // UNDECIDABLE 이 아무리 많아도 위반이 0이면 0이다 — 커버리지는 리포트가 낸다.
        Path pcap = write(dir, "capture.pcap", capture(
            frame("10.0.9.99", 40000, "10.0.2.11", 502, WRITE_REQUEST),
            frame("10.0.2.11", 502, "10.0.9.99", 40000, WRITE_RESPONSE)));
        Path policy = write(dir, "policy.yaml", POLICY);

        assertEquals(1, Huginn.run(new String[]{pcap.toString(), policy.toString()}));
    }

    @Test
    void 같은_입력에_같은_리포트가_나온다() {
        byte[] pcap = capture(
            frame("10.0.9.99", 40000, "10.0.2.11", 502, WRITE_REQUEST),
            frame("10.0.2.11", 502, "10.0.9.99", 40000, WRITE_RESPONSE),
            frame("10.0.1.20", 40000, "10.0.2.11", 502, READ_REQUEST),
            frame("10.0.2.11", 502, "10.0.1.20", 40000, READ_RESPONSE));

        assertEquals(Pipeline.run(pcap, POLICY).render(), Pipeline.run(pcap, POLICY).render());
    }

    private static Path write(Path dir, String name, byte[] bytes) throws IOException {
        Path path = dir.resolve(name);
        Files.write(path, bytes);
        return path;
    }

    private static Path write(Path dir, String name, String text) throws IOException {
        Path path = dir.resolve(name);
        Files.writeString(path, text, StandardCharsets.UTF_8);
        return path;
    }
}
