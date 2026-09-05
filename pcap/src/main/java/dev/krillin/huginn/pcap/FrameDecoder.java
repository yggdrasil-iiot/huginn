package dev.krillin.huginn.pcap;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * {@link CapturedPacket} 의 원시 바이트에서 Ethernet 을 벗기고, IPv4 를 벗기고, TCP 를 벗겨
 * {@link TcpSegment} 를 뽑는다. 이름이 {@code LinkLayerDecoder} 가 아닌 이유 — 링크 계층만이
 * 아니라 네트워크(IPv4)와 전송(TCP)까지 벗겨낸다.
 * <p>이 층의 결함은 전부 조용히 데이터를 잃는 방식으로 나타난다: VLAN 판정이 틀리면
 * VLAN 캡처 전체가 사라져 "위반 0건"이 된다. 그래서 이 클래스는 예외를 던지지 않는다 —
 * 대상이 아닌 패킷은 {@link DecodedFrames#skipped()} 로 세고 넘어간다.
 * <p>{@code pcap} 모듈은 아무 것도 의존하지 않는다 — 이 클래스도 마찬가지다.
 */
public final class FrameDecoder {

    private static final int ETH_HEADER_LEN = 14;
    private static final int VLAN_TAG_LEN = 4;
    private static final int ETHERTYPE_IPV4 = 0x0800;
    private static final int ETHERTYPE_VLAN_8100 = 0x8100;
    private static final int ETHERTYPE_VLAN_88A8 = 0x88A8;
    private static final int MIN_IPV4_HEADER_LEN = 20;
    private static final int MIN_TCP_HEADER_LEN = 20;
    private static final int PROTOCOL_TCP = 6;
    private static final int FLAG_MF = 0x2000;
    private static final int MASK_FRAGMENT_OFFSET = 0x1FFF;
    private static final int TCP_FLAG_SYN = 0x02;
    private static final int TCP_FLAG_ACK = 0x10;

    private FrameDecoder() {
    }

    public static DecodedFrames decode(List<CapturedPacket> packets) {
        List<TcpSegment> segments = new ArrayList<>();
        int skipped = 0;
        for (CapturedPacket packet : packets) {
            TcpSegment segment = decodeOne(packet);
            if (segment == null) {
                skipped++;
            } else {
                segments.add(segment);
            }
        }
        return new DecodedFrames(segments, skipped);
    }

    private static TcpSegment decodeOne(CapturedPacket packet) {
        byte[] data = packet.data();

        // ---- Ethernet ----------------------------------------------------------------
        if (data.length < ETH_HEADER_LEN) {
            return null;
        }
        int ethertype = readU16(data, 12);
        int offset = ETH_HEADER_LEN;
        // VLAN 태그는 if 가 아니라 반복으로 벗긴다 — QinQ(이중 태그)가 실존한다.
        while (ethertype == ETHERTYPE_VLAN_8100 || ethertype == ETHERTYPE_VLAN_88A8) {
            if (data.length < offset + VLAN_TAG_LEN) {
                return null;
            }
            ethertype = readU16(data, offset + 2);
            offset += VLAN_TAG_LEN;
        }
        if (ethertype != ETHERTYPE_IPV4) {
            return null;
        }

        // ---- IPv4 -----------------------------------------------------------------
        if (data.length < offset + MIN_IPV4_HEADER_LEN) {
            return null;
        }
        int ihl = data[offset] & 0x0F;
        if (ihl < 5) {
            return null;
        }
        int ipHeaderLen = ihl * 4;
        if (data.length < offset + ipHeaderLen) {
            return null;
        }
        int totalLength = readU16(data, offset + 2);
        if (totalLength == 0) {
            // TSO/GSO 오프로드를 켠 송신 호스트의 캡처에서 실제로 나온다.
            // 유도 길이가 음수가 되어 어차피 걸리지만, 의도된 처리임을 남긴다.
            return null;
        }
        int flagsAndFragOffset = readU16(data, offset + 6);
        boolean moreFragments = (flagsAndFragOffset & FLAG_MF) != 0;
        int fragmentOffset = flagsAndFragOffset & MASK_FRAGMENT_OFFSET;
        if (fragmentOffset != 0 || moreFragments) {
            return null;
        }
        int protocol = data[offset + 9] & 0xFF;
        if (protocol != PROTOCOL_TCP) {
            return null;
        }
        String sourceAddress = readIp(data, offset + 12);
        String targetAddress = readIp(data, offset + 16);

        // ---- TCP --------------------------------------------------------------------
        int tcpStart = offset + ipHeaderLen;
        if (data.length < tcpStart + MIN_TCP_HEADER_LEN) {
            return null;
        }
        int dataOffset = (data[tcpStart + 12] >> 4) & 0x0F;
        if (dataOffset < 5) {
            return null;
        }
        int tcpHeaderLen = dataOffset * 4;
        if (data.length < tcpStart + tcpHeaderLen) {
            return null;
        }

        int sourcePort = readU16(data, tcpStart);
        int targetPort = readU16(data, tcpStart + 2);
        long sequence = readU32(data, tcpStart + 4) & 0xFFFFFFFFL;
        int flags = data[tcpStart + 13] & 0xFF;
        boolean syn = (flags & TCP_FLAG_SYN) != 0;
        boolean ack = (flags & TCP_FLAG_ACK) != 0;

        // ---- 페이로드: IP 헤더가 유도한 길이를 따른다, 남은 바이트가 아니라 -------------------
        int payloadStart = tcpStart + tcpHeaderLen;
        int derivedPayloadLen = totalLength - ipHeaderLen - tcpHeaderLen;
        if (derivedPayloadLen < 0) {
            return null;
        }
        int available = data.length - payloadStart;
        boolean clamped = false;
        int actualPayloadLen = derivedPayloadLen;
        if (derivedPayloadLen > available) {
            actualPayloadLen = available;
            clamped = true;
        }
        byte[] payload = Arrays.copyOfRange(data, payloadStart, payloadStart + actualPayloadLen);

        boolean truncated = packet.truncated() || clamped;

        return new TcpSegment(packet.at(), sourceAddress, sourcePort, targetAddress, targetPort,
            sequence, payload, truncated, syn, ack);
    }

    /** 16비트 필드는 부호 있는 short 로 읽으면 안 된다 — 0x8100 이 -32512 가 되어 비교가 거짓이 된다. */
    private static int readU16(byte[] data, int pos) {
        return ((data[pos] & 0xFF) << 8) | (data[pos + 1] & 0xFF);
    }

    private static long readU32(byte[] data, int pos) {
        return ((long) (data[pos] & 0xFF) << 24)
            | ((data[pos + 1] & 0xFF) << 16)
            | ((data[pos + 2] & 0xFF) << 8)
            | (data[pos + 3] & 0xFF);
    }

    private static String readIp(byte[] data, int pos) {
        return (data[pos] & 0xFF) + "." + (data[pos + 1] & 0xFF) + "."
            + (data[pos + 2] & 0xFF) + "." + (data[pos + 3] & 0xFF);
    }
}
