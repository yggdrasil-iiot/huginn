package dev.krillin.huginn.decode;

import dev.krillin.huginn.pcap.TcpStream;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 수용 규칙 — 이 설계와 1차 원칙의 경계선이 여기서 고정된다. */
class RunReaderTest {

    private static TcpStream withRuns(long missing, byte[]... runs) {
        return new TcpStream(Instant.EPOCH, "10.0.0.1", 1000, "10.0.0.2", 502,
            List.of(runs), missing, false, false);
    }

    @Test
    void 첫_구간은_조건_없이_받는다() {
        // 지금 동작 그대로다 — 잔여가 남아도 받는다. 이 성질이 갭 없는 스트림의 동작을 보존한다.
        byte[] withGarbage = ModbusFixtures.concat(
            ModbusFixtures.mbap(1, 1, 3, ModbusFixtures.pdu(0, 2)),
            "GET / HTTP/1.1\r\n".getBytes(StandardCharsets.US_ASCII));

        var reading = RunReader.read(withRuns(0, withGarbage), ModbusFramer::frames);

        assertEquals(1, reading.accepted().size());
        assertEquals(16, reading.unreadBytes(), "첫 구간의 잔여는 그대로 센다");
        assertEquals(0, reading.rejectedRuns());
    }

    @Test
    void 이후_구간은_잔여가_0일_때만_받는다() {
        byte[] clean = ModbusFixtures.mbap(1, 1, 3, ModbusFixtures.pdu(0, 2));
        byte[] dirty = ModbusFixtures.concat(clean, new byte[]{0x01, 0x02, 0x03});

        var accepted = RunReader.read(withRuns(50, clean, clean), ModbusFramer::frames);
        assertEquals(2, accepted.accepted().size());
        assertEquals(0, accepted.unreadBytes());
        assertEquals(0, accepted.rejectedRuns());

        var rejected = RunReader.read(withRuns(50, clean, dirty), ModbusFramer::frames);
        assertEquals(1, rejected.accepted().size(), "지저분한 구간은 통째로 버린다");
        assertEquals(dirty.length, rejected.unreadBytes(), "잔여만 세면 버린 양을 축소 보고한다");
        assertEquals(1, rejected.rejectedRuns());
        assertEquals(1, rejected.dirtyRuns(), "프레임이 나왔는데 버린 구간 — 설계 §7 의 반증 지표");
    }

    @Test
    void 프레임이_하나도_없는_이후_구간은_거부한다() {
        byte[] clean = ModbusFixtures.mbap(1, 1, 3, ModbusFixtures.pdu(0, 2));
        byte[] garbage = "SSH-2.0-OpenSSH_9.0\r\n".getBytes(StandardCharsets.US_ASCII);

        var reading = RunReader.read(withRuns(50, clean, garbage), ModbusFramer::frames);

        assertEquals(1, reading.accepted().size());
        assertEquals(garbage.length, reading.unreadBytes());
        assertEquals(1, reading.rejectedRuns());
        assertEquals(0, reading.dirtyRuns(), "프레임이 없었으므로 지저분한 구간이 아니다");
    }

    @Test
    void 연결_설정만_든_구간은_미해독_바이트가_아니다() {
        // 2차가 못박은 원칙 — 비-S7 TPKT 는 미해독이 아니다. 구간 길이를 통째로 세면 그게 깨진다.
        byte[] job = S7Fixtures.job(S7Fixtures.readVar(S7Fixtures.sym(0, 0x52, 16)));

        var reading = RunReader.read(
            withRuns(50, job, S7Fixtures.connectRequest()), S7Framer::frames);

        assertEquals(1, reading.accepted().size());
        assertEquals(0, reading.unreadBytes(), "버려졌지만 미해독 바이트는 아니다");
        assertEquals(1, reading.rejectedRuns(), "버려진 사실은 진단에 남는다");
    }

    @Test
    void 구간이_없으면_전부_0이다() {
        var reading = RunReader.read(withRuns(0), ModbusFramer::frames);

        assertTrue(reading.accepted().isEmpty());
        assertEquals(0, reading.unreadBytes());
        assertEquals(0, reading.capturedBytes());
    }

    @Test
    void 받은_바이트를_전부_센다() {
        byte[] clean = ModbusFixtures.mbap(1, 1, 3, ModbusFixtures.pdu(0, 2));

        var reading = RunReader.read(withRuns(997, clean, clean), ModbusFramer::frames);

        assertEquals(clean.length * 2L, reading.capturedBytes(),
            "구멍은 여기 안 든다 — missingBytes 가 따로 센다");
    }
}
