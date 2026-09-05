package dev.krillin.huginn.pcap;

import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PcapReaderTest {

    @Test
    void 빈_캡처는_패킷이_없다() {
        assertTrue(PcapReader.read(PcapBuilder.ethernet().build()).isEmpty());
    }

    @Test
    void 패킷의_시각과_바이트를_보존한다() {
        byte[] pcap = PcapBuilder.ethernet().packet(1_700_000_000, 500_000, new byte[]{1, 2, 3}).build();
        List<CapturedPacket> packets = PcapReader.read(pcap);
        assertEquals(1, packets.size());
        assertEquals(Instant.ofEpochSecond(1_700_000_000L, 500_000_000L), packets.get(0).at());
        assertArrayEquals(new byte[]{1, 2, 3}, packets.get(0).data());
        assertFalse(packets.get(0).truncated());
    }

    @Test
    void 절단된_패킷을_절단으로_표시한다() {
        // tcpdump -s 96 같은 설정에서는 모든 패킷이 잘려 온다.
        // 잘린 것을 온전한 것처럼 하류로 흘리면 프레임 경계가 어긋난다.
        byte[] pcap = PcapBuilder.ethernet().packet(1, 0, new byte[]{1, 2, 3}, 1500).build();
        CapturedPacket p = PcapReader.read(pcap).get(0);
        assertTrue(p.truncated());
        assertEquals(1500, p.originalLength());
    }

    @Test
    void 매직넘버가_틀리면_즉시_실패한다() {
        assertThrows(PcapException.class, () -> PcapReader.read(PcapBuilder.withMagic(0xDEADBEEF).build()));
    }

    @Test
    void 빅엔디언_pcap은_원인을_밝히며_거부한다() {
        PcapException e = assertThrows(PcapException.class,
            () -> PcapReader.read(PcapBuilder.withMagic(PcapBuilder.MAGIC_BIG_ENDIAN).build()));
        assertTrue(e.getMessage().contains("빅엔디언"));
    }

    @Test
    void 나노초_해상도_pcap은_원인을_밝히며_거부한다() {
        PcapException e = assertThrows(PcapException.class,
            () -> PcapReader.read(PcapBuilder.withMagic(PcapBuilder.MAGIC_NANOS).build()));
        assertTrue(e.getMessage().contains("나노초"));
    }

    @Test
    void pcapng는_원인을_밝히며_거부한다() {
        // Wireshark 기본 저장 형식이라 사용자가 가장 흔히 만난다.
        // "매직넘버가 틀림" 으로만 거부하면 원인을 못 찾는다.
        PcapException e = assertThrows(PcapException.class,
            () -> PcapReader.read(PcapBuilder.withMagic(PcapBuilder.MAGIC_PCAPNG).build()));
        assertTrue(e.getMessage().contains("pcapng"));
    }

    @Test
    void 지원하지_않는_링크타입이면_즉시_실패한다() {
        // 부분 결과를 내면 "위반 0건" 이 안전으로 오독된다.
        assertThrows(PcapException.class, () -> PcapReader.read(PcapBuilder.withLinkType(228).build()));
    }

    @Test
    void 글로벌_헤더가_잘리면_즉시_실패한다() {
        assertThrows(PcapException.class, () -> PcapReader.read(new byte[10]));
        assertThrows(PcapException.class, () -> PcapReader.read(new byte[0]));
    }

    @Test
    void 패킷_데이터가_잘리면_즉시_실패한다() {
        byte[] full = PcapBuilder.ethernet().packet(1, 0, new byte[]{1, 2, 3, 4}).build();
        assertThrows(PcapException.class, () -> PcapReader.read(Arrays.copyOf(full, full.length - 2)));
    }

    @Test
    void 선언_길이가_비정상적으로_크면_OOM이_아니라_예외다() {
        // 잔여 바이트 검사가 없으면 선언 길이를 그대로 믿고 읽으러 간다.
        // 이 케이스는 양수 경로를 막는다 — 부호 비트 경로는 아래 테스트가 맡는다.
        assertThrows(PcapException.class, () -> PcapReader.read(PcapBuilder.ethernet()
            .packetWithDeclaredLength(1, 0, new byte[]{1, 2}, 0x7FFFFFFF).build()));
    }

    @Test
    void 선언_길이의_부호비트가_서_있어도_예외다() {
        // 0x7FFFFFFF 는 양수라 부호 비트 경로를 타지 않는다.
        // 마스킹이 없으면 0xFFFFFFFF 는 -1 로 읽혀 잔여 검사를 통과하고 new byte[-1] 에서 터진다.
        assertThrows(PcapException.class, () -> PcapReader.read(PcapBuilder.ethernet()
            .packetWithDeclaredLength(1, 0, new byte[]{1, 2}, 0xFFFFFFFF).build()));
    }

    @Test
    void 타임스탬프의_부호비트가_서_있어도_미래_시각으로_읽는다() {
        // ts_sec 은 2038 년 이후 부호 비트가 선다. 마스킹하지 않으면 1901 년으로 읽혀
        // Observation.at 이 통째로 뒤집힌다 — 리포트의 시간축이 무의미해진다.
        // 0xFFFFFFFF 는 int 로 -1 이다. 마스킹하면 4,294,967,295 초 = 2106 년.
        CapturedPacket p = PcapReader.read(PcapBuilder.ethernet()
            .packet(0xFFFFFFFF, 0, new byte[]{1, 2}).build()).get(0);
        assertEquals(Instant.ofEpochSecond(4_294_967_295L), p.at());
    }
}
