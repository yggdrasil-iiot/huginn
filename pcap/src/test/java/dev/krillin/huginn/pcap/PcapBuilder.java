package dev.krillin.huginn.pcap;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

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
}
