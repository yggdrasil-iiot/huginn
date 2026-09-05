package dev.krillin.huginn.pcap;

import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FrameDecoderTest {

    private List<CapturedPacket> readAsPackets(byte[]... frames) {
        PcapBuilder builder = PcapBuilder.ethernet();
        for (byte[] frame : frames) {
            builder.packet(1, 0, frame);
        }
        return PcapReader.read(builder.build());
    }

    private List<CapturedPacket> readAsSnappedPackets(byte[] frame, int originalLength) {
        return PcapReader.read(PcapBuilder.ethernet().packet(1, 0, frame, originalLength).build());
    }

    private TcpSegment decodeSingle(byte[] frame) {
        return FrameDecoder.decode(readAsPackets(frame)).segments().get(0);
    }

    @Test
    void TCP_세그먼트의_4튜플과_페이로드를_뽑는다() {
        byte[] frame = PcapBuilder.ethernetIpv4Tcp("10.0.1.20", 40000, "10.0.2.11", 502,
            1000, PcapBuilder.FLAG_ACK, new byte[]{'a', 'b', 'c'}, 0, 0, 0);
        TcpSegment s = decodeSingle(frame);
        assertEquals("10.0.1.20", s.sourceAddress());
        assertEquals(40000, s.sourcePort());
        assertEquals("10.0.2.11", s.targetAddress());
        assertEquals(502, s.targetPort());
        assertEquals(1000L, s.sequence());
        assertArrayEquals(new byte[]{'a', 'b', 'c'}, s.payload());
    }

    @Test
    void 이더넷_패딩이_페이로드에_섞이지_않는다() {
        // 짧은 프레임은 60바이트로 패딩된다. 캡처 잔여 바이트로 자르면 0바이트가 스트림에 섞이고,
        // 그 0들이 응용 계층 프레임의 길이 필드 경계 탐색을 어긋나게 한다.
        byte[] frame = PcapBuilder.ethernetIpv4Tcp("10.0.1.20", 40000, "10.0.2.11", 502,
            1000, PcapBuilder.FLAG_ACK, new byte[]{1, 2, 3}, 0, 0, /* ethPadTo */ 60);
        TcpSegment s = decodeSingle(frame);
        assertArrayEquals(new byte[]{1, 2, 3}, s.payload());
    }

    @Test
    void SYN과_ACK_비트를_세그먼트에_싣는다() {
        // 청크 3 의 클라이언트 판정이 이 두 비트에 전적으로 기댄다. 여기서 싣지 않으면
        // 조립기의 sawSynOnly 가 아예 계산 불가능하다.
        TcpSegment syn = decodeSingle(PcapBuilder.ethernetIpv4Tcp("10.0.1.20", 40000,
            "10.0.2.11", 502, 1000, PcapBuilder.FLAG_SYN, new byte[0], 0, 0, 0));
        assertTrue(syn.syn());
        assertFalse(syn.ack(), "클라이언트 SYN 에는 ACK 가 없다");

        TcpSegment synAck = decodeSingle(PcapBuilder.ethernetIpv4Tcp("10.0.2.11", 502,
            "10.0.1.20", 40000, 7000, PcapBuilder.FLAG_SYN | PcapBuilder.FLAG_ACK, new byte[0], 0, 0, 0));
        assertTrue(synAck.syn());
        assertTrue(synAck.ack(), "SYN+ACK 를 SYN 과 구별하지 못하면 서버가 클라이언트로 읽힌다");
    }

    @Test
    void IP_옵션이_있어도_헤더_길이를_보고_페이로드를_찾는다() {
        byte[] frame = PcapBuilder.ethernetIpv4Tcp("10.0.1.20", 40000, "10.0.2.11", 502,
            1000, PcapBuilder.FLAG_ACK, new byte[]{9, 8, 7}, /* ipOptionBytes */ 4, 0, 0);
        TcpSegment s = decodeSingle(frame);
        assertArrayEquals(new byte[]{9, 8, 7}, s.payload());
    }

    @Test
    void TCP_옵션이_있어도_데이터_오프셋을_보고_페이로드를_찾는다() {
        byte[] frame = PcapBuilder.ethernetIpv4Tcp("10.0.1.20", 40000, "10.0.2.11", 502,
            1000, PcapBuilder.FLAG_ACK, new byte[]{4, 5, 6}, 0, /* tcpOptionBytes */ 12, 0);
        TcpSegment s = decodeSingle(frame);
        assertArrayEquals(new byte[]{4, 5, 6}, s.payload());
    }

    @Test
    void VLAN_태그가_붙어도_해독한다() {
        // 산업망에서는 VLAN 이 오히려 기본이다. 조용히 건너뛰면
        // VLAN 캡처 전체가 사라지고 "위반 0건" 이 나온다 — 설계 §7 이 위험하다고 못박은 상황이다.
        byte[] frame = PcapBuilder.vlanTagged("10.0.1.20", 40000, "10.0.2.11", 502,
            1000, new byte[]{1, 2, 3}, 100);
        assertArrayEquals(new byte[]{1, 2, 3}, decodeSingle(frame).payload());
    }

    @Test
    void 이중_VLAN_태그도_벗긴다() {
        // QinQ. if 한 번으로 벗기면 안쪽 태그가 남아 ethertype 자리에서 0x8100 을 읽고
        // IPv4 가 아니라고 건너뛴다 — 캡처가 통째로 사라진다.
        byte[] frame = PcapBuilder.vlanTagged("10.0.1.20", 40000, "10.0.2.11", 502,
            1000, new byte[]{1, 2, 3}, 100, 200);
        assertArrayEquals(new byte[]{1, 2, 3}, decodeSingle(frame).payload());
    }

    @Test
    void IPv4가_아니면_대상_외로_센다() {
        // ARP.
        DecodedFrames d = FrameDecoder.decode(readAsPackets(
            PcapBuilder.ethernetWithEthertype(0x0806, new byte[28])));
        assertEquals(1, d.skipped());
        assertTrue(d.segments().isEmpty());
    }

    @Test
    void TCP가_아니면_대상_외로_센다() {
        // UDP.
        DecodedFrames d = FrameDecoder.decode(readAsPackets(
            PcapBuilder.ethernetIpv4Udp("10.0.1.20", 40000, "10.0.2.11", 502, new byte[]{1, 2, 3})));
        assertEquals(1, d.skipped());
        assertTrue(d.segments().isEmpty());
    }

    @Test
    void 단편화된_조각은_대상_외로_센다() {
        // fragment offset != 0 인 조각에는 TCP 헤더가 없다. 있다고 가정하고 파싱하면 쓰레기를 읽는다.
        // 페이로드는 유효한 TCP 헤더처럼 보이는 바이트로 채운다 — 0 으로 채우면 offset 검사를
        // 지운 구현도 dataOffset < 5 에 걸려 같은 답을 내고 테스트가 공허해진다.
        byte[] fakeTcpHeader = new byte[20];
        ByteBuffer bb = ByteBuffer.wrap(fakeTcpHeader).order(ByteOrder.BIG_ENDIAN);
        bb.putShort((short) 12345);   // src port
        bb.putShort((short) 502);     // dst port
        bb.putInt(9999);              // seq
        bb.putInt(0);                 // ack
        fakeTcpHeader[12] = 0x50;     // dataOffset 5, reserved 0 — 유효해 보이는 헤더
        fakeTcpHeader[13] = (byte) PcapBuilder.FLAG_ACK;

        byte[] frame = PcapBuilder.ipv4Fragment("10.0.1.20", 40000, "10.0.2.11", 502, 1000,
            /* fragmentOffset */ 185, /* moreFragments */ false, fakeTcpHeader);
        DecodedFrames d = FrameDecoder.decode(readAsPackets(frame));
        assertEquals(1, d.skipped());
        assertTrue(d.segments().isEmpty());
    }

    @Test
    void MF가_선_첫_조각도_대상_외다() {
        // offset == 0 이라 TCP 헤더는 있지만 페이로드가 뒤 조각으로 이어진다.
        // 온전한 세그먼트로 취급하면 응용 계층 길이 필드가 실제보다 길어 다음 경계가 어긋난다.
        // TCP 헤더가 온전하므로 MF 검사를 빼면 유효 세그먼트가 나와 skipped == 0 이 된다 —
        // 정확히 그 이유로 실패하는 테스트다.
        byte[] frame = PcapBuilder.ipv4Fragment("10.0.1.20", 40000, "10.0.2.11", 502, 1000,
            /* fragmentOffset */ 0, /* moreFragments */ true, new byte[]{1, 2, 3});
        DecodedFrames d = FrameDecoder.decode(readAsPackets(frame));
        assertEquals(1, d.skipped());
        assertTrue(d.segments().isEmpty());
    }

    @Test
    void 헤더보다_짧은_프레임은_예외가_아니라_대상_외다() {
        // IndexOutOfBoundsException 이 아니라 정의된 동작이어야 한다.
        DecodedFrames d = FrameDecoder.decode(readAsPackets(new byte[]{1, 2, 3}));
        assertEquals(1, d.skipped());
        assertTrue(d.segments().isEmpty());
    }

    @Test
    void 헤더는_온전한데_페이로드가_잘리면_절단으로_표시하고_버리지_않는다() {
        // snaplen 절단의 정상 경로다. 유도 길이만큼 자르려 들면 IndexOutOfBoundsException 이 난다.
        // Task 6 의 절단 픽스처는 이더넷 헤더보다 짧아 이 경로에 닿지 않는다.
        byte[] fullFrame = PcapBuilder.ethernetIpv4Tcp("10.0.1.20", 40000, "10.0.2.11", 502,
            1000, PcapBuilder.FLAG_ACK, new byte[]{1, 2, 3, 4, 5}, 0, 0, 0);
        // 헤더(14+20+20=54바이트)는 온전히 남기고, 5바이트 페이로드 중 앞 2바이트만 남긴다.
        // incl_len == orig_len(둘 다 56)으로 둬서 CapturedPacket.truncated() 는 false 다 —
        // 이 테스트가 잡는 것은 오직 IP totalLength 로 유도한 길이가 실제 남은 바이트보다 큰 경우의
        // 클램프 동작이다(다음 테스트가 CapturedPacket 수준 절단을 따로 검증한다).
        byte[] snapped = java.util.Arrays.copyOf(fullFrame, 56);
        List<CapturedPacket> packets = readAsPackets(snapped);
        assertFalse(packets.get(0).truncated());
        TcpSegment s = FrameDecoder.decode(packets).segments().get(0);
        assertTrue(s.truncated());
        assertArrayEquals(new byte[]{1, 2}, s.payload());
    }

    @Test
    void pcap_수준_절단이_세그먼트_절단으로_전파된다() {
        // truncated 는 CapturedPacket.truncated() 와 잘라내기의 OR 인데, 다른 테스트는
        // 전부 incl_len == orig_len 이라 앞 절반을 한 번도 시험하지 않는다.
        // CapturedPacket.truncated() 를 통째로 무시하는 구현이 나머지를 전부 통과하고,
        // 그러면 tcpdump -s 96 캡처에서 청크 3 의 절단 관찰이 조용히 무력해진다.
        byte[] frame = PcapBuilder.ethernetIpv4Tcp("10.0.1.20", 40000, "10.0.2.11", 502,
            1000, PcapBuilder.FLAG_ACK, new byte[]{1, 2, 3}, 0, 0, 0);
        TcpSegment s = FrameDecoder.decode(readAsSnappedPackets(frame, 1500)).segments().get(0);
        assertTrue(s.truncated(), "페이로드는 온전해도 캡처가 잘렸으면 절단이다");
        assertArrayEquals(new byte[]{1, 2, 3}, s.payload());
    }

    @Test
    void 대상_외_패킷_수를_보고한다() {
        // "아무것도 못 읽었다" 를 드러내려면 건너뛴 수를 알아야 한다.
        DecodedFrames d = FrameDecoder.decode(readAsPackets(
            PcapBuilder.ethernetWithEthertype(0x0806, new byte[28]),                        // ARP
            PcapBuilder.ethernetIpv4Udp("10.0.1.20", 40000, "10.0.2.11", 502, new byte[]{1, 2, 3})));
        assertEquals(2, d.skipped());
        assertTrue(d.segments().isEmpty());
    }
}
