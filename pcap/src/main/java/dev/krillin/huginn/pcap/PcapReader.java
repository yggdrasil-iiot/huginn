package dev.krillin.huginn.pcap;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * 합성/실제 libpcap(클래식, pcapng 아님) 바이트열을 {@link CapturedPacket} 목록으로 읽는다.
 * <p>포맷 변형은 조용히 무시하거나 부분 결과를 내는 대신 즉시 {@link PcapException} 으로
 * 거부한다 — 위반 0건인 리포트는 "안전하다"로 오독되기 때문이다. 메시지는 항상 원인을
 * 이름 붙여 말한다: "빅엔디언", "나노초 해상도", "pcapng" 처럼, 그냥 "매직넘버가 틀림"이 아니라.
 * <p>이 모듈은 아무 것도 의존하지 않는다 — 다른 huginn 모듈도, 서드파티 라이브러리도.
 * 파싱은 전부 손으로 작성한다.
 */
public final class PcapReader {

    private static final int GLOBAL_HEADER_LEN = 24;
    private static final int PACKET_HEADER_LEN = 16;
    private static final int LINKTYPE_ETHERNET = 1;

    private PcapReader() {
    }

    public static List<CapturedPacket> read(byte[] bytes) {
        if (bytes.length < GLOBAL_HEADER_LEN) {
            throw new PcapException(
                "pcap 글로벌 헤더가 잘렸다 (필요: " + GLOBAL_HEADER_LEN + " 바이트, 실제: " + bytes.length + " 바이트)");
        }

        ByteBuffer buf = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN);

        int magic = buf.getInt();
        checkMagic(magic);

        buf.getShort(); // version_major
        buf.getShort(); // version_minor
        buf.getInt();   // thiszone
        buf.getInt();   // sigfigs
        buf.getInt();   // snaplen — 소비자가 없어 값을 쓰지 않는다
        int linkType = buf.getInt();
        if (linkType != LINKTYPE_ETHERNET) {
            throw new PcapException("지원하지 않는 링크타입: " + linkType + " (Ethernet(1)만 지원한다)");
        }

        List<CapturedPacket> packets = new ArrayList<>();
        while (buf.remaining() > 0) {
            if (buf.remaining() < PACKET_HEADER_LEN) {
                throw new PcapException(
                    "패킷 헤더가 잘렸다 (필요: " + PACKET_HEADER_LEN + " 바이트, 잔여: " + buf.remaining() + " 바이트)");
            }

            long tsSec = buf.getInt() & 0xFFFFFFFFL;
            long tsUsec = buf.getInt() & 0xFFFFFFFFL;
            long inclLen = buf.getInt() & 0xFFFFFFFFL;
            long origLen = buf.getInt() & 0xFFFFFFFFL;

            if (inclLen > buf.remaining()) {
                throw new PcapException(
                    "패킷 데이터가 잘렸다 (선언 길이: " + inclLen + " 바이트, 잔여: " + buf.remaining() + " 바이트)");
            }

            byte[] data = new byte[(int) inclLen];
            buf.get(data);

            Instant at = Instant.ofEpochSecond(tsSec, tsUsec * 1000L);
            packets.add(new CapturedPacket(at, data, origLen));
        }

        return packets;
    }

    private static void checkMagic(int magic) {
        if (magic == MagicNumbers.MICROS) {
            return;
        }
        if (magic == MagicNumbers.BIG_ENDIAN) {
            throw new PcapException("빅엔디언 pcap 은 지원하지 않는다 (매직: 0x" + Integer.toHexString(magic) + ")");
        }
        if (magic == MagicNumbers.NANOS) {
            throw new PcapException("나노초 해상도 pcap 은 지원하지 않는다 (매직: 0x" + Integer.toHexString(magic) + ")");
        }
        if (magic == MagicNumbers.PCAPNG) {
            throw new PcapException("pcapng 형식은 지원하지 않는다 — 클래식 libpcap(.pcap) 형식으로 다시 저장하라");
        }
        throw new PcapException("알 수 없는 매직넘버: 0x" + Integer.toHexString(magic));
    }

    /**
     * libpcap 글로벌 헤더 매직넘버 상수. {@code pcap} 메인 소스는 테스트 전용 {@code PcapBuilder}
     * (test-jar)를 참조할 수 없으므로, 같은 값을 여기 따로 정의한다. 두 정의가 갈라지면
     * 테스트가 즉시 잡아낸다.
     */
    private static final class MagicNumbers {
        static final int MICROS = 0xA1B2C3D4;
        static final int NANOS = 0xA1B23C4D;
        static final int BIG_ENDIAN = 0xD4C3B2A1;
        static final int PCAPNG = 0x0A0D0D0A;
    }
}
