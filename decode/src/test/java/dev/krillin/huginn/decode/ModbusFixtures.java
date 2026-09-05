package dev.krillin.huginn.decode;

import java.io.ByteArrayOutputStream;

/**
 * Modbus/TCP 바이트 픽스처. Task 11·12·13 의 decode 테스트는 물론 Task 14 의 cli E2E 도
 * test-jar 를 통해 이것을 그대로 쓴다 — 그래서 클래스도 세 메서드도 전부 public 이다
 * (private 생성자만 예외). 복제하면 두 벌이 갈라진다.
 */
public final class ModbusFixtures {

    private ModbusFixtures() {
    }

    /** MBAP 한 프레임. length = 2 + pduBody.length (유닛ID 1 + 함수코드 1 + 본문). */
    public static byte[] mbap(int tid, int uid, int fc, byte[] pduBody) {
        int length = 2 + pduBody.length;
        byte[] frame = new byte[6 + length];
        frame[0] = (byte) (tid >>> 8);
        frame[1] = (byte) tid;
        frame[2] = 0;
        frame[3] = 0;
        frame[4] = (byte) (length >>> 8);
        frame[5] = (byte) length;
        frame[6] = (byte) uid;
        frame[7] = (byte) fc;
        System.arraycopy(pduBody, 0, frame, 8, pduBody.length);
        return frame;
    }

    /** 시작 주소·수량을 빅엔디언 2바이트씩 이어 붙인 4바이트(함수코드는 포함하지 않는다). */
    public static byte[] pdu(int startAddress, int quantity) {
        return new byte[] {
            (byte) (startAddress >>> 8), (byte) startAddress,
            (byte) (quantity >>> 8), (byte) quantity
        };
    }

    /** 프레임 여러 개를 한 스트림으로 잇는다. */
    public static byte[] concat(byte[]... parts) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] part : parts) {
            out.writeBytes(part);
        }
        return out.toByteArray();
    }
}
