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
    void S7_프레임_관찰_수는_첫_갭까지의_커버리지와_같다() throws Exception {
        // tshark 의 ROSCTR 1 개수는 23,732 / 86,403 / 53,217 이지만 Huginn 은 그보다 적게 본다.
        // **차이는 전부 설계 §8 의 세 번째 원인으로 설명된다** — tshark 는 TCP 를 재조립하지만
        // Huginn 은 contiguousPrefix, 즉 첫 갭까지만 읽는다(1차 설계 §5-③).
        //
        // 클라이언트 방향(10.10.10.20:49156 → 10.10.10.10:102)의 실측:
        //   151020  세그먼트 47,431 · 전체 2,403,943 B · 갭 5 개 · 첫 갭이 오프셋 297  → 커버리지  0.01%
        //   151021  세그먼트 172,651 · 전체 8,547,957 B · 갭 1 개 · 첫 갭이 5,200,371 → 커버리지 60.84%
        //   151022  세그먼트 106,379 · 전체 5,267,097 B · 갭 1 개 · 첫 갭이 3,378,474 → 커버리지 64.14%
        //
        // 관찰 비율은 0.09% / 60.88% / 64.18% 로 그 커버리지와 일치한다. 프레이밍이나 방향
        // 판정의 결함이 아니라 재조립 정책의 대가이며, 그 정책은 1차가 의도적으로 고른 것이다.
        // 캡처의 구멍은 진짜다 — 151020 은 오프셋 297 에서 51,183 바이트가 통째로 비어 있다.
        assertEquals(21, frameObservations(s7Only("4SICS-GeekLounge-151020.pcap")));
        assertEquals(52_607, frameObservations(s7Only("4SICS-GeekLounge-151021.pcap")));
        assertEquals(34_154, frameObservations(s7Only("4SICS-GeekLounge-151022.pcap")));
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
        // 양방향 요청 대화가 0 이 아닌 것은 반증이 아니라 Job 수와 관찰 수가 벌어지는 정당한
        // 원인이다(설계 §8). 단언하지 않고 찍어서 samples/README.md 로 옮긴다.
        for (String capture : CAPTURES) {
            ObservationResult s7 = s7Only(capture);
            Diagnosed both = TrafficObserver.observeWithDiagnostics(
                streamsOf(capture), List.of(new ModbusDecoder(), new S7Decoder()));

            System.out.printf(
                "%s%n  S7 전용: 총 관찰 %d · 프레임 관찰 %d · UNDECIDABLE 관찰 %d · "
                    + "해독 대화 %d · UNDECIDABLE 대화 %d · 대상 외 대화 %d%n"
                    + "  둘 다 등록: 다중 주장 %d · 양방향 요청 대화 %d%n",
                capture,
                s7.observations().size(), frameObservations(s7), undecidableCount(s7),
                s7.decodedConversations(), s7.undecidableConversations(), s7.skippedConversations(),
                both.multiClaimConversations(), both.bothDirectionRequestConversations());
        }
    }
}
