package dev.krillin.huginn.decode;

import dev.krillin.huginn.pcap.TcpStream;
import dev.krillin.huginn.reconcile.Observation;
import dev.krillin.huginn.reconcile.Protocol;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static dev.krillin.huginn.decode.S7Fixtures.sym;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

/** 두 프로토콜이 한 캡처에 섞였을 때의 계수와, 프레이머 배타성. */
class CoexistenceTest {

    private static TcpStream stream(String src, int sport, String dst, int dport, byte[] bytes) {
        return new TcpStream(Instant.EPOCH, src, sport, dst, dport,
            bytes.length == 0 ? List.of() : List.of(bytes), 0, false, false);
    }

    private final TcpStream modbusStream = stream("10.0.1.20", 40000, "10.0.2.11", 502,
        ModbusFixtures.mbap(1, 1, 3, ModbusFixtures.pdu(0, 2)));
    private final TcpStream s7Stream = stream("10.0.1.30", 2000, "10.0.2.12", 102,
        S7Fixtures.job(S7Fixtures.readVar(sym(0, 0x52, 16))));
    private final TcpStream sshStream = stream("10.0.1.20", 40002, "10.0.3.5", 22,
        "SSH-2.0-OpenSSH_9.0\r\n".getBytes(StandardCharsets.US_ASCII));

    @Test
    void 한_캡처에_두_프로토콜이_섞여도_계수의_합이_전체_대화_수다() {
        ObservationResult r = TrafficObserver.observe(List.of(modbusStream, s7Stream, sshStream));

        assertEquals(3, r.decodedConversations() + r.undecidableConversations()
            + r.skippedConversations());
        assertEquals(2, r.decodedConversations());
        assertEquals(1, r.skippedConversations());
        assertEquals(0, r.undecidableConversations());
    }

    @Test
    void 두_프로토콜의_관찰이_한_목록에_섞여_나온다() {
        // 프로토콜별 분리는 하지 않는다(설계 §6) — 같은 칸에 센다.
        ObservationResult r = TrafficObserver.observe(List.of(modbusStream, s7Stream));

        assertEquals(2, r.observations().size());
        assertEquals(Set.of(Protocol.MODBUS_TCP, Protocol.S7COMM),
            r.observations().stream().map(Observation::protocol).collect(Collectors.toSet()));
    }

    @Test
    void 한_대화의_두_방향이_서로_다른_해독기에_걸리면_등록_순서가_이긴다() {
        // 스트림 단위 불가능성은 대화 단위로 올라가지 못한다(설계 §3).
        // Modbus 가 먼저 등록돼 있으므로 반대 방향의 S7 Job 은 버려진다 — 그것을 고정한다.
        TcpStream modbusDirection = stream("10.0.1.40", 3000, "10.0.2.50", 3001,
            ModbusFixtures.mbap(1, 1, 3, ModbusFixtures.pdu(0, 2)));
        TcpStream s7DirectionSameTuple = stream("10.0.2.50", 3001, "10.0.1.40", 3000,
            S7Fixtures.job(S7Fixtures.readVar(sym(0, 0x52, 16))));

        Diagnosed d = TrafficObserver.observeWithDiagnostics(
            List.of(modbusDirection, s7DirectionSameTuple),
            List.of(new ModbusDecoder(), new S7Decoder()));

        assertEquals(1, d.multiClaimConversations());
        assertEquals(Protocol.MODBUS_TCP, d.result().observations().get(0).protocol(),
            "등록 순서상 첫 번째가 이긴다");
    }

    @Test
    void 어떤_바이트열도_두_프레이머에_동시에_걸리지_않는다() {
        // 오프셋 0 의 바이트 2~3 은 MBAP 에선 프로토콜 ID(반드시 0), TPKT 에선 전체 길이(>= 7)다.
        // 두 프레이머가 **서로 모순되게** 제약하는 유일한 자리이므로 그 65,536 개 값을 전부 돌린다.
        //
        // 고정 프레임의 두 바이트만 덮어쓰면 나머지가 그 값에 대해 무효가 되어 사실상 두 경우만
        // 검사하게 된다. 값마다 나머지가 유효한 후보를 새로 만들어야 시험이 된다.
        //
        // 후보가 최대 64KB 라 이 루프는 수 GB 를 할당했다 버린다. 10초 안팎 걸릴 수 있다.
        for (int value = 0; value <= 0xFFFF; value++) {
            byte[] mbap = ModbusFixtures.mbap(0x0300, 1, 3, ModbusFixtures.pdu(0, 2));
            mbap[2] = (byte) (value >>> 8);
            mbap[3] = (byte) value;
            assertFalse(claimedByBoth(mbap), "MBAP 후보 protocolId=0x" + Integer.toHexString(value));

            // S7 후보 — TPKT 길이가 실제로 value 인 프레임을 만든다.
            // 전체 = 4(TPKT) + 3(COTP) + 10(S7 헤더) + 파라미터 → 파라미터 = value - 17.
            if (value >= 18) {
                byte[] parameter = new byte[value - 17];
                parameter[0] = 0x04;
                byte[] s7 = S7Fixtures.job(parameter);
                assertEquals(value, ((s7[2] & 0xFF) << 8) | (s7[3] & 0xFF), "픽스처가 길이를 맞췄는가");
                assertFalse(claimedByBoth(s7), "S7 후보 TPKT len=" + value);
            }
        }
    }

    /** 두 <b>실제</b> 프레이머를 돌린다 — 수용 조건을 테스트가 재구현하면 사본을 검증하게 된다. */
    private boolean claimedByBoth(byte[] candidate) {
        return !ModbusFramer.frames(candidate).frames().isEmpty()
            && !S7Framer.frames(candidate).frames().isEmpty();
    }
}
