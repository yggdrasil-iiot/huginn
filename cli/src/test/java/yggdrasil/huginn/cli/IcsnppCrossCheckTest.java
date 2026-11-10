package yggdrasil.huginn.cli;

import yggdrasil.huginn.decode.TrafficObserver;
import yggdrasil.huginn.pcap.FrameDecoder;
import yggdrasil.huginn.pcap.PcapReader;
import yggdrasil.huginn.pcap.TcpStreamAssembler;
import yggdrasil.huginn.reconcile.Access;
import yggdrasil.huginn.reconcile.Observation;
import yggdrasil.huginn.zeek.ZeekLogReader;
import yggdrasil.huginn.zeek.ZeekLogs;
import yggdrasil.huginn.zeek.ZeekObserver;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.function.Function;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * 같은 트레이스를 두 길로 읽고 맞춰 본다 — Huginn 의 해독기(pcap)와 Zeek ICSNPP(커밋된 기준 로그).
 * 둘 다 "이 요청을 읽었다" 고 주장하므로, 판정한 요청이 다르면 어느 한쪽의 결함이다. 어느 쪽도
 * 정답으로 두지 않는다.
 *
 * <p>트레이스는 저장소에 넣지 않는다. {@code scripts/fetch-icsnpp-traces.sh} 가 고정 커밋에서 받아
 * 해시를 대조하고, {@code HUGINN_ICSNPP_TRACES} 가 그 디렉터리를 가리킬 때만 돈다. 가리켰는데
 * 파일이 없으면 건너뛰지 않고 실패한다.
 *
 * <p><b>맞추지 않는 것</b>은 한 곳에 적는다: 시각(두 길의 {@code at} 의미가 다르다), UNDECIDABLE
 * (pcap 은 대화 꼬리를, 로그는 Userdata 요청을 남긴다), 그리고 로그에 없는 대상 표기 — S7 변수 주소,
 * PLC Control 서비스 이름, Modbus FC 23 주소와 FC 43 장치 식별 코드.
 */
@EnabledIfEnvironmentVariable(named = "HUGINN_ICSNPP_TRACES", matches = ".+")
class IcsnppCrossCheckTest {

    private static List<Observation> pcap(String trace) throws Exception {
        Path path = Path.of(System.getenv("HUGINN_ICSNPP_TRACES"), trace);
        return TrafficObserver.observe(TcpStreamAssembler.assemble(
            FrameDecoder.decode(PcapReader.read(Files.readAllBytes(path))).segments())).observations();
    }

    private static List<Observation> log(String... resources) {
        List<yggdrasil.huginn.zeek.ZeekLog> logs = new ArrayList<>();
        for (String resource : resources) {
            logs.add(ZeekLogReader.parse(ZeekLogs.icsnpp(resource), resource));
        }
        return ZeekObserver.observe(logs).observations();
    }

    private static Map<String, Long> decided(List<Observation> observations, Function<Observation, String> ref) {
        return observations.stream()
            .filter(o -> o.access() != Access.UNDECIDABLE)
            .collect(Collectors.groupingBy(
                o -> o.source() + " > " + o.target() + " " + o.protocol() + " " + o.access() + " " + ref.apply(o),
                TreeMap::new, Collectors.counting()));
    }

    @Test
    void snap7_은_두_길이_같은_요청을_같게_판정한다() throws Exception {
        List<Observation> fromPcap = pcap("snap7.pcap");
        List<Observation> fromLog = log("s7comm-snap7/s7comm.log");

        // 변수 주소는 로그에 없다 — READ/WRITE 는 대상 없이, 제어는 이름표까지 맞춘다.
        Function<Observation, String> s7 = o -> switch (o.access()) {
            case READ, WRITE -> "var";
            default -> o.objectRef().replaceFirst(" \\(.*\\)$", "");
        };
        assertEquals(decided(fromPcap, s7), decided(fromLog, s7));
        assertEquals(21, decided(fromLog, s7).values().stream().mapToLong(Long::longValue).sum());
    }

    @Test
    void modbus_example_은_대상_표기까지_같다() throws Exception {
        List<Observation> fromPcap = pcap("modbus_example.pcap");
        List<Observation> fromLog = log("modbus-basic/modbus_detailed.log");

        // 로그에 없는 둘만 pcap 쪽 표기로 옮긴다: FC 23 의 읽기 시작 주소(holding:40002, 두 건)와
        // FC 43 의 Read Device ID 코드(device-id:1, 한 건). 그 밖의 대상 표기는 그대로 같아야 한다.
        Function<Observation, String> ref = o -> switch (o.objectRef()) {
            case "fc:23" -> "holding:40002";
            case "fc:43" -> "device-id:1";
            default -> o.objectRef();
        };
        assertEquals(decided(fromPcap, Observation::objectRef), decided(fromLog, ref));
        assertEquals(24, fromLog.size());
    }
}
