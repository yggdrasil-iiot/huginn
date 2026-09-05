package dev.krillin.huginn.decode;

import java.io.ByteArrayOutputStream;

/**
 * S7comm 바이트 픽스처. 프레임을 손으로 짜면 길이 필드를 매번 다시 계산해야 하고,
 * 그 계산이 틀리면 테스트가 프레이머가 아니라 픽스처를 검증하게 된다.
 *
 * <p>{@code ModbusFixtures} 선례를 따라 클래스도 메서드도 전부 public 이다(private 생성자만 예외) —
 * B단계의 {@code cli} E2E 가 test-jar 로 이것을 그대로 쓴다.
 */
public final class S7Fixtures {

    public static final int ROSCTR_JOB = 1;
    public static final int ROSCTR_ACK_DATA = 3;
    public static final int ROSCTR_USERDATA = 7;

    private S7Fixtures() {
    }

    /** ROSCTR 1. parameter 는 함수코드부터 시작한다. */
    public static byte[] job(byte[] parameter) {
        return frame(ROSCTR_JOB, parameter, new byte[0], true);
    }

    /** ROSCTR 3 — 헤더에 오류 클래스·코드 2바이트가 더 붙는다. */
    public static byte[] ackData(byte[] parameter, byte[] data) {
        return frame(ROSCTR_ACK_DATA, parameter, data, true);
    }

    /** ROSCTR 7. */
    public static byte[] userdata(byte[] parameter) {
        return frame(ROSCTR_USERDATA, parameter, new byte[0], true);
    }

    /** EOT 비트가 꺼진 조각. 프레이머는 여기서 멈춰야 한다. */
    public static byte[] fragmented(byte[] parameter) {
        return frame(ROSCTR_JOB, parameter, new byte[0], false);
    }

    /** COTP 연결 요청(CR, 0xE0) — TPKT 로는 유효하지만 S7 이 아니다. */
    public static byte[] connectRequest() {
        byte[] cotp = {0x11, (byte) 0xE0, 0, 0, 0, 1, 0, (byte) 0xC0, 1, 0x0A,
                       (byte) 0xC1, 2, 1, 2, (byte) 0xC2, 2, 1, 2};
        return tpkt(cotp);
    }

    /** 0x04 Read Var. */
    public static byte[] readVar(byte[]... items) {
        return varParameter(0x04, items);
    }

    /** 0x05 Write Var. */
    public static byte[] writeVar(byte[]... items) {
        return varParameter(0x05, items);
    }

    /**
     * 0x29 PLC Stop. 뒤따르는 서비스 문자열은 우리가 읽지 않으므로 형태만 갖춘다 —
     * 픽스처가 파서보다 많이 알면 테스트가 구현이 아니라 픽스처를 검증하게 된다.
     */
    public static byte[] plcStop() {
        return new byte[] {0x29, 0, 0, 0, 0, 0, 0, 0, 0, 5, 'P', '_', 'P', 'R', 'O'};
    }

    /** 0x1A Request download — 엔지니어링 워크스테이션이 PLC 에 로직을 내려받는 시작점. */
    public static byte[] downloadRequest() {
        return new byte[] {0x1A, 0, 0, 0, 0, 0, 0, 0, 9,
                           '_', '0', '8', '0', '0', 'A', 'P', '0', '0'};
    }

    /** 0xF0 Setup Communication — 파라미터에 항목이 없다. */
    public static byte[] setupCommunication() {
        return new byte[] {(byte) 0xF0, 0, 0, 1, 0, 1, 0, (byte) 0xF0};
    }

    /** 1200SYM(0xb2) 주소 항목. */
    public static byte[] sym(int area1, int area2, int... lids) {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        body.write(0xB2);                     // syntax id
        body.write(0xFF);                     // reserved
        writeU16(body, area1);
        writeU16(body, area2);
        body.writeBytes(new byte[] {(byte) 0xEA, 0x2D, (byte) 0xB0, (byte) 0xD9});   // CRC
        for (int lid : lids) {
            body.write(0x40 | ((lid >>> 24) & 0x0F));   // LID flags 4 = Obtain by LID
            body.write((lid >>> 16) & 0xFF);
            body.write((lid >>> 8) & 0xFF);
            body.write(lid & 0xFF);
        }
        return item(body.toByteArray());
    }

    /** S7ANY(0x10) 주소 항목. address 는 바이트 주소, bit 는 0~7. */
    public static byte[] s7any(int area, int dbNumber, int address, int bit) {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        body.write(0x10);                     // syntax id
        body.write(0x02);                     // transport size = BYTE
        writeU16(body, 1);                    // length
        writeU16(body, dbNumber);
        body.write(area);
        int bitAddress = address * 8 + bit;
        body.write((bitAddress >>> 16) & 0xFF);
        body.write((bitAddress >>> 8) & 0xFF);
        body.write(bitAddress & 0xFF);
        return item(body.toByteArray());
    }

    public static byte[] concat(byte[]... parts) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] part : parts) {
            out.writeBytes(part);
        }
        return out.toByteArray();
    }

    /** TPKT 로 감싼다 — 길이는 헤더 4바이트를 포함한다. */
    public static byte[] tpkt(byte[] payload) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(0x03);
        out.write(0x00);
        writeU16(out, 4 + payload.length);
        out.writeBytes(payload);
        return out.toByteArray();
    }

    /** 항목 하나를 {@code 12 <len> <body>} 로 감싼다 — len 은 syntax id 부터 센다. */
    private static byte[] item(byte[] body) {
        if (body.length > 255) {
            throw new IllegalArgumentException("항목 길이 필드는 1바이트다: " + body.length);
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(0x12);
        out.write(body.length);
        out.writeBytes(body);
        return out.toByteArray();
    }

    private static byte[] varParameter(int function, byte[]... items) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(function);
        out.write(items.length);
        for (byte[] one : items) {
            out.writeBytes(one);
        }
        return out.toByteArray();
    }

    private static byte[] frame(int rosctr, byte[] parameter, byte[] data, boolean endOfTransmission) {
        ByteArrayOutputStream s7 = new ByteArrayOutputStream();
        s7.write(0x32);
        s7.write(rosctr);
        writeU16(s7, 0);                       // redundancy id
        writeU16(s7, 0x0100);                  // pdu reference
        writeU16(s7, parameter.length);
        writeU16(s7, data.length);
        if (rosctr == 2 || rosctr == 3) {
            s7.write(0);                       // error class
            s7.write(0);                       // error code
        }
        s7.writeBytes(parameter);
        s7.writeBytes(data);

        ByteArrayOutputStream cotp = new ByteArrayOutputStream();
        cotp.write(0x02);                                    // li
        cotp.write(0xF0);                                    // DT Data
        cotp.write(endOfTransmission ? 0x80 : 0x00);         // tpdu number | eot
        cotp.writeBytes(s7.toByteArray());
        return tpkt(cotp.toByteArray());
    }

    private static void writeU16(ByteArrayOutputStream out, int value) {
        out.write((value >>> 8) & 0xFF);
        out.write(value & 0xFF);
    }
}
