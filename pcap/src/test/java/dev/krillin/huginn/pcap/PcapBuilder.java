package dev.krillin.huginn.pcap;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

/**
 * 테스트용 pcap 조립기. 외부 캡처 파일 없이 결정적으로 검증하기 위한 것이다.
 * <p>Task 14 의 cli E2E 테스트가 test-jar 를 통해 이것을 그대로 쓴다 — 그래서 클래스도
 * 정적 팩터리도 인스턴스 메서드도 전부 public 이다(private 생성자만 예외).
 * 클래스만 public 으로 두면 다른 패키지에서 ethernet() 부터 막힌다. 복제하면 두 벌이 갈라진다.
 * withSnaplen 은 PcapReader 가 snaplen 을 읽지도 쓰지도 않아 소비자가 없으므로 두지 않는다.
 */
public final class PcapBuilder {

    public static final int MAGIC_MICROS = 0xA1B2C3D4;
    public static final int MAGIC_NANOS  = 0xA1B23C4D;
    public static final int MAGIC_BIG_ENDIAN = 0xD4C3B2A1;
    public static final int MAGIC_PCAPNG = 0x0A0D0D0A;

    private final ByteArrayOutputStream out = new ByteArrayOutputStream();

    public static PcapBuilder ethernet() { return new PcapBuilder(1, MAGIC_MICROS, 65535); }
    public static PcapBuilder withMagic(int magic) { return new PcapBuilder(1, magic, 65535); }
    public static PcapBuilder withLinkType(int linkType) { return new PcapBuilder(linkType, MAGIC_MICROS, 65535); }

    private PcapBuilder(int linkType, int magic, int snaplen) {
        ByteBuffer h = ByteBuffer.allocate(24).order(ByteOrder.LITTLE_ENDIAN);
        h.putInt(magic).putShort((short) 2).putShort((short) 4)
         .putInt(0).putInt(0).putInt(snaplen).putInt(linkType);
        out.writeBytes(h.array());
    }

    /** 온전한 패킷 — incl_len == orig_len */
    public PcapBuilder packet(int seconds, int micros, byte[] payload) {
        return packet(seconds, micros, payload, payload.length);
    }

    /** 절단된 패킷 — incl_len(실제 저장) < orig_len(원본) */
    public PcapBuilder packet(int seconds, int micros, byte[] stored, int originalLength) {
        ByteBuffer h = ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN);
        h.putInt(seconds).putInt(micros).putInt(stored.length).putInt(originalLength);
        out.writeBytes(h.array());
        out.writeBytes(stored);
        return this;
    }

    /** 손상·악의적 파일 — 선언 길이가 실제 잔여보다 크다 */
    public PcapBuilder packetWithDeclaredLength(int seconds, int micros, byte[] stored, int declaredInclLen) {
        ByteBuffer h = ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN);
        h.putInt(seconds).putInt(micros).putInt(declaredInclLen).putInt(declaredInclLen);
        out.writeBytes(h.array());
        out.writeBytes(stored);
        return this;
    }

    public byte[] build() { return out.toByteArray(); }

    // ---- Task 7: 프레임 조립 헬퍼 ------------------------------------------------------

    /** TCP 플래그 비트. 데이터 세그먼트는 보통 ACK 만 서 있다. */
    public static final int FLAG_SYN = 0x02, FLAG_ACK = 0x10;

    /**
     * Ethernet(14) + IPv4(20 + options) + TCP(20 + options) 프레임을 조립한다.
     * 체크섬은 0으로 둔다 — 리더가 검증하지 않는다(손상 탐지는 이 도구의 목적이 아니다).
     *
     * @param tcpFlags   TCP 헤더 오프셋 13에 그대로 넣는다. 데이터 세그먼트는 FLAG_ACK,
     *                   클라이언트 SYN 은 FLAG_SYN, 서버 SYN+ACK 는 FLAG_SYN | FLAG_ACK.
     * @param ethPadTo   이 길이에 못 미치면 0으로 채운다. 이더넷 최소 프레임(60) 재현용.
     */
    public static byte[] ethernetIpv4Tcp(String srcIp, int srcPort, String dstIp, int dstPort,
                                  long seq, int tcpFlags, byte[] payload,
                                  int ipOptionBytes, int tcpOptionBytes, int ethPadTo) {
        byte[] tcpHeader = tcpHeader(srcPort, dstPort, seq, tcpFlags, tcpOptionBytes);
        byte[] tcpSegment = concat(tcpHeader, payload);
        byte[] ipHeader = ipv4Header(6, tcpSegment.length, srcIp, dstIp, ipOptionBytes, 0);
        byte[] frame = concat(ethernetHeader(0x0800), ipHeader, tcpSegment);
        if (frame.length < ethPadTo) {
            frame = Arrays.copyOf(frame, ethPadTo);
        }
        return frame;
    }

    /**
     * VLAN 태그를 끼운 변형.
     *
     * @param vlanIds 바깥에서 안쪽 순서. 하나면 802.1Q, 둘이면 QinQ 이중 태그다.
     *                이중 태그를 만들 수 없으면 "if 가 아니라 반복" 규칙에 테스트가 붙지 않는다.
     */
    public static byte[] vlanTagged(String srcIp, int srcPort, String dstIp, int dstPort,
                             long seq, byte[] payload, int... vlanIds) {
        byte[] tcpHeader = tcpHeader(srcPort, dstPort, seq, FLAG_ACK, 0);
        byte[] tcpSegment = concat(tcpHeader, payload);
        byte[] ipHeader = ipv4Header(6, tcpSegment.length, srcIp, dstIp, 0, 0);

        ByteArrayOutputStream frame = new ByteArrayOutputStream();
        frame.writeBytes(macAddresses());
        for (int i = 0; i < vlanIds.length; i++) {
            int tpid = (i == 0 && vlanIds.length > 1) ? 0x88A8 : 0x8100;
            int tci = vlanIds[i] & 0x0FFF;
            frame.write((tpid >> 8) & 0xFF);
            frame.write(tpid & 0xFF);
            frame.write((tci >> 8) & 0xFF);
            frame.write(tci & 0xFF);
        }
        frame.write(0x08);
        frame.write(0x00);
        frame.writeBytes(ipHeader);
        frame.writeBytes(tcpSegment);
        return frame.toByteArray();
    }

    /** UDP 프레임 — 대상이 아님을 확인하는 용도. */
    public static byte[] ethernetIpv4Udp(String srcIp, int srcPort, String dstIp, int dstPort, byte[] payload) {
        int udpLength = 8 + payload.length;
        byte[] udpHeader = new byte[8];
        udpHeader[0] = (byte) ((srcPort >> 8) & 0xFF);
        udpHeader[1] = (byte) (srcPort & 0xFF);
        udpHeader[2] = (byte) ((dstPort >> 8) & 0xFF);
        udpHeader[3] = (byte) (dstPort & 0xFF);
        udpHeader[4] = (byte) ((udpLength >> 8) & 0xFF);
        udpHeader[5] = (byte) (udpLength & 0xFF);
        // udpHeader[6..7] 체크섬 = 0

        byte[] udpSegment = concat(udpHeader, payload);
        byte[] ipHeader = ipv4Header(17, udpSegment.length, srcIp, dstIp, 0, 0);
        return concat(ethernetHeader(0x0800), ipHeader, udpSegment);
    }

    /**
     * 단편화된 IPv4. protocol 은 6(TCP)이고, **fragmentOffset == 0 이면 정상적인 20바이트 TCP
     * 헤더(dataOffset 5, 4-튜플, seq, FLAG_ACK)를 채운다.**
     * <p>포트·seq 인자가 없으면 IP 페이로드가 0으로 차서 dataOffset == 0 이 되고,
     * MF·offset 검사를 **아예 구현하지 않은** 디코더도 `dataOffset < 5` 규칙에 걸려 똑같이
     * skipped 를 낸다 — 두 단편화 테스트가 초록으로 통과하면서 아무것도 시험하지 않게 된다.
     *
     * @param fragmentOffset 0 이 아니면 TCP 헤더가 아예 없다(그 자리부터 페이로드다).
     * @param moreFragments  MF 플래그. offset == 0 이라도 MF 가 서 있으면 첫 조각이라
     *                       페이로드가 뒤 조각으로 이어져 프레임 경계를 믿을 수 없다.
     */
    public static byte[] ipv4Fragment(String srcIp, int srcPort, String dstIp, int dstPort, long seq,
                               int fragmentOffset, boolean moreFragments, byte[] payload) {
        byte[] ipPayload;
        if (fragmentOffset == 0) {
            byte[] tcpHeader = tcpHeader(srcPort, dstPort, seq, FLAG_ACK, 0);
            ipPayload = concat(tcpHeader, payload);
        } else {
            ipPayload = payload;
        }
        int flagsAndFragOffset = (moreFragments ? 0x2000 : 0) | (fragmentOffset & 0x1FFF);
        byte[] ipHeader = ipv4Header(6, ipPayload.length, srcIp, dstIp, 0, flagsAndFragOffset);
        return concat(ethernetHeader(0x0800), ipHeader, ipPayload);
    }

    /** 임의 ethertype 프레임 — ARP(0x0806) 등 IPv4 가 아닌 것을 만든다. */
    public static byte[] ethernetWithEthertype(int ethertype, byte[] body) {
        return concat(ethernetHeader(ethertype), body);
    }

    // ---- 내부 조립 유틸 -----------------------------------------------------------------

    private static byte[] macAddresses() {
        return new byte[]{0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 1};
    }

    private static byte[] ethernetHeader(int ethertype) {
        byte[] h = new byte[14];
        System.arraycopy(macAddresses(), 0, h, 0, 12);
        h[12] = (byte) ((ethertype >> 8) & 0xFF);
        h[13] = (byte) (ethertype & 0xFF);
        return h;
    }

    private static byte[] ipv4Header(int protocol, int payloadLength, String srcIp, String dstIp,
                                      int optionBytes, int flagsAndFragOffset) {
        int ihl = 5 + optionBytes / 4;
        int totalLength = ihl * 4 + payloadLength;
        byte[] h = new byte[ihl * 4];
        h[0] = (byte) ((4 << 4) | ihl);
        h[1] = 0; // DSCP/ECN
        h[2] = (byte) ((totalLength >> 8) & 0xFF);
        h[3] = (byte) (totalLength & 0xFF);
        h[4] = 0x12;
        h[5] = 0x34; // identification — 임의값
        h[6] = (byte) ((flagsAndFragOffset >> 8) & 0xFF);
        h[7] = (byte) (flagsAndFragOffset & 0xFF);
        h[8] = 64; // TTL
        h[9] = (byte) protocol;
        h[10] = 0;
        h[11] = 0; // 체크섬 = 0
        byte[] src = ipToBytes(srcIp);
        byte[] dst = ipToBytes(dstIp);
        System.arraycopy(src, 0, h, 12, 4);
        System.arraycopy(dst, 0, h, 16, 4);
        // h[20 .. 20+optionBytes) 는 옵션 — 0으로 채워둔다(이미 배열 초기값)
        return h;
    }

    private static byte[] tcpHeader(int srcPort, int dstPort, long seq, int flags, int optionBytes) {
        int dataOffset = 5 + optionBytes / 4;
        byte[] h = new byte[dataOffset * 4];
        h[0] = (byte) ((srcPort >> 8) & 0xFF);
        h[1] = (byte) (srcPort & 0xFF);
        h[2] = (byte) ((dstPort >> 8) & 0xFF);
        h[3] = (byte) (dstPort & 0xFF);
        h[4] = (byte) ((seq >> 24) & 0xFF);
        h[5] = (byte) ((seq >> 16) & 0xFF);
        h[6] = (byte) ((seq >> 8) & 0xFF);
        h[7] = (byte) (seq & 0xFF);
        // h[8..11] ack number = 0
        h[12] = (byte) ((dataOffset << 4) & 0xF0);
        h[13] = (byte) (flags & 0xFF);
        // h[14..15] window, h[16..17] 체크섬, h[18..19] urgent pointer 는 0
        return h;
    }

    private static byte[] ipToBytes(String ip) {
        String[] parts = ip.split("\\.");
        byte[] b = new byte[4];
        for (int i = 0; i < 4; i++) {
            b[i] = (byte) Integer.parseInt(parts[i]);
        }
        return b;
    }

    private static byte[] concat(byte[]... parts) {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        for (byte[] p : parts) {
            b.writeBytes(p);
        }
        return b.toByteArray();
    }
}
