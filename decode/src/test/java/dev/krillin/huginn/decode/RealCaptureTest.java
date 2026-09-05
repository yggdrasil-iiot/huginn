package dev.krillin.huginn.decode;

import dev.krillin.huginn.pcap.FrameDecoder;
import dev.krillin.huginn.pcap.PcapReader;
import dev.krillin.huginn.pcap.TcpStream;
import dev.krillin.huginn.pcap.TcpStreamAssembler;
import dev.krillin.huginn.reconcile.Access;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * 4SICS 실캡처 회귀·진단. {@code HUGINN_SAMPLES} 가 캡처 디렉터리를 가리킬 때만 돈다 —
 * 캡처는 라이선스가 제각각이라 저장소에 넣지 않는다.
 *
 * <pre>
 * # PowerShell
 * $env:HUGINN_SAMPLES = "C:/path/to/huginn/samples"   # 절대 경로 — surefire 작업 디렉터리는 모듈 basedir 다
 * mvn -pl decode -am test -Dtest=RealCaptureTest -Dsurefire.failIfNoSpecifiedTests=false
 * </pre>
 */
@EnabledIfEnvironmentVariable(named = "HUGINN_SAMPLES", matches = ".+")
class RealCaptureTest {

    private static final List<String> CAPTURES = List.of(
        "4SICS-GeekLounge-151020.pcap",
        "4SICS-GeekLounge-151021.pcap",
        "4SICS-GeekLounge-151022.pcap");

    private static List<TcpStream> streamsOf(String capture) throws Exception {
        Path path = Path.of(System.getenv("HUGINN_SAMPLES"), capture);
        return TcpStreamAssembler.assemble(
            FrameDecoder.decode(PcapReader.read(Files.readAllBytes(path))).segments());
    }

    private static ObservationResult s7Only(String capture) throws Exception {
        return TrafficObserver.observe(streamsOf(capture), List.of(new S7Decoder()));
    }

    private static long undecidableCount(ObservationResult r) {
        return r.observations().stream().filter(o -> o.access() == Access.UNDECIDABLE).count();
    }

    /** 프레임에서 나온 관찰만 센다 — 순회기가 만든 관찰은 objectRef 가 "-" 다. */
    private static long frameObservations(ObservationResult r) {
        return r.observations().stream().filter(o -> !"-".equals(o.objectRef())).count();
    }

    @Test
    void Modbus_판정은_1차와_한_치도_다르지_않다() throws Exception {
        // S7 을 켜면 총계는 당연히 움직인다. Modbus 만 등록해 1차 기준선과 대조한다.
        ObservationResult r = TrafficObserver.observe(
            streamsOf("4SICS-GeekLounge-151022.pcap"), List.of(new ModbusDecoder()));

        assertEquals(56, r.decodedConversations());
        assertEquals(932_655, r.skippedConversations());
        assertEquals(24, r.undecidableConversations());
        assertEquals(48, undecidableCount(r), "UNDECIDABLE 관찰");
        assertEquals(49_767, r.observations().size(), "관찰 총수");
    }

    @Test
    void S7_프레임_관찰_수가_tshark_Job_수와_정확히_일치한다() throws Exception {
        // 갭 이후 구간을 엄격 적합으로 읽기 전에는 21 / 52,607 / 34,154 였다 — 첫 갭까지만
        // 읽었기 때문이다(클라이언트 방향 커버리지 0.01% / 60.84% / 64.14%).
        //
        // 이제 tshark 의 ROSCTR 1 개수와 **정확히** 맞는다. 근사가 아니라 완전 일치이며,
        // 남을 수 있었던 두 원인(양방향 요청 대화·거부된 구간)이 이 데이터셋에서는 0 이다.
        assertEquals(23_732, frameObservations(s7Only("4SICS-GeekLounge-151020.pcap")));
        assertEquals(86_403, frameObservations(s7Only("4SICS-GeekLounge-151021.pcap")));
        assertEquals(53_217, frameObservations(s7Only("4SICS-GeekLounge-151022.pcap")));
    }

    @Test
    void 지저분한_구간은_하나도_없다() throws Exception {
        // 설계 §7 의 첫 반증 조건. 프레임이 나오면서도 잔여가 남는 갭 이후 구간이 있으면
        // "엄격 적합이 경계 정렬을 보장한다" 는 전제가 틀린 것이다.
        //
        // 갭이 패킷 단위로 생기고 한 패킷이 온전한 프레임을 나르므로 재개 지점이 프레임
        // 경계에 떨어진다 — 0 이라는 사실 자체를 회귀로 지킨다.
        for (String capture : CAPTURES) {
            Diagnosed d = TrafficObserver.observeWithDiagnostics(
                streamsOf(capture), List.of(new S7Decoder()));
            assertEquals(0, d.dirtyRuns(), capture);
        }
    }

    @Test
    void 대상_외_대화가_줄지_않았다() throws Exception {
        // 설계 §7 의 둘째 반증 조건. 비산업 트래픽의 갭 이후 구간이 엄격 적합을 통과하면
        // 이 수가 줄고, 그것이 곧 오탐이다.
        int[] expected = {7_288, 112_730, 932_647};
        for (int i = 0; i < CAPTURES.size(); i++) {
            Diagnosed d = TrafficObserver.observeWithDiagnostics(
                streamsOf(CAPTURES.get(i)), List.of(new ModbusDecoder(), new S7Decoder()));
            assertEquals(expected[i], d.result().skippedConversations(), CAPTURES.get(i));
        }
    }

    @Test
    void 두_해독기가_한_대화를_주장하는_일은_없다() throws Exception {
        // 설계 §9 의 반증 조건. 0 이 아니면 등록 순서 규칙이 실제로 프레임을 버리고 있다.
        for (String capture : CAPTURES) {
            Diagnosed d = TrafficObserver.observeWithDiagnostics(
                streamsOf(capture), List.of(new ModbusDecoder(), new S7Decoder()));
            assertEquals(0, d.multiClaimConversations(), capture);
        }
    }

    @Test
    void 수치를_기록한다() throws Exception {
        // 진단까지 함께 찍는다 — dirtyRuns 가 0 인지가 설계 §7 의 첫 반증 조건이다.
        // 양방향 요청 대화가 0 이 아닌 것은 반증이 아니라 Job 수와 관찰 수가 벌어지는 정당한
        // 원인이다(설계 §8). 단언하지 않고 찍어서 samples/README.md 로 옮긴다.
        for (String capture : CAPTURES) {
            Diagnosed s7 = TrafficObserver.observeWithDiagnostics(
                streamsOf(capture), List.of(new S7Decoder()));
            Diagnosed both = TrafficObserver.observeWithDiagnostics(
                streamsOf(capture), List.of(new ModbusDecoder(), new S7Decoder()));
            ObservationResult r = s7.result();

            System.out.printf(
                "%s%n  S7 only: total=%d frame=%d undecidable=%d decoded=%d undecConv=%d skipped=%d%n"
                    + "  bytes: unobserved=%d industrial=%d%n"
                    + "  runs: rejected=%d dirty=%d%n"
                    + "  both: multiClaim=%d bothDirReq=%d skipped=%d%n",
                capture,
                r.observations().size(), frameObservations(r), undecidableCount(r),
                r.decodedConversations(), r.undecidableConversations(), r.skippedConversations(),
                r.unobservedBytes(), r.industrialBytes(),
                s7.rejectedRuns(), s7.dirtyRuns(),
                both.multiClaimConversations(), both.bothDirectionRequestConversations(),
                both.result().skippedConversations());
        }
    }
}
