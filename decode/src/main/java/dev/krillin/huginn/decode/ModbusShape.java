package dev.krillin.huginn.decode;

import java.util.List;

/**
 * 한 프레임 또는 한 방향이 요청인지 응답인지. 단정할 수 없으면 UNKNOWN 이다.
 * <p><b>왜 프레임 구조인가.</b> 포트만으로 방향을 판정하면 거울상을 원리적으로 구별할 수 없다 —
 * "낮은 쪽이 서버"라는 전제는 낮은 쪽이 정말 리스닝 포트일 때만 참인데 포트 번호만 보고는
 * 확인할 방법이 없다. 설계 §5-① 의 "포트가 아니라 프레이밍으로 판정한다" 를 방향 판정에도
 * 그대로 적용한다.
 * <p>판정 근거는 <b>MODBUS Application Protocol Specification V1.1b3</b> §4.1·§6.1~§6.19 이며,
 * 요청과 응답의 PDU 길이가 겹치지 않는 함수코드만 형태를 낸다. <b>애매하면 UNKNOWN 이다 —
 * 단정이 오검출보다 비싸다.</b>
 * <p>표에 없는 함수코드가 UNKNOWN 인 이유(나중에 "쉬운 승리"라며 추가하지 않도록): 5·6·22 는
 * 응답이 요청의 에코고(§6.5·§6.6·§6.16), 20 은 양쪽 다 {@code 1+카운트}(§6.14), 21 은 명시적
 * 에코(§6.15), 23 은 11바이트 이상에서 완전히 겹친다(§6.17). 43 은 MEI 타입 종속이다(§6.19·§6.21).
 * 7·8·11·12 는 "(Serial Line only)" 라 Modbus/TCP 캡처에 나타나지 않는다.
 */
public enum ModbusShape {
    REQUEST_ONLY, RESPONSE_ONLY, UNKNOWN;

    public static ModbusShape of(int functionCode, byte[] pdu) {
        int fc = u(functionCode);
        int length = pdu.length;

        // §4.1 — 128~255 는 예외 응답 전용이라 요청일 수 없다. 이 행이 없으면 예외 응답만
        // 실린 서버 방향이 형태를 내지 못한다. ModbusAccess.of 가 이미 UNDECIDABLE 이라
        // 방향을 특정해도 위반이 생기지 않으므로 부작용도 없다.
        if (fc >= 0x80) {
            return length == 1 ? RESPONSE_ONLY : UNKNOWN;
        }

        return switch (fc) {
            case 3, 4 -> registerRead(pdu);    // 주소2+수량2 = 4 · 응답은 1 + 2N (짝수 바이트수)
            case 1, 2 -> bitRead(pdu);         // 주소2+수량2 = 4 · 응답은 1 + ⌈수량/8⌉
            case 15, 16 -> multiWrite(pdu);    // 요청 5 + 바이트수 · 응답은 정확히 4
            default -> UNKNOWN;
        };
    }

    /** 각 프레임의 형태를 모은다. 두 형태가 섞이면 다수결로 밀어붙이지 않고 UNKNOWN 이다. */
    public static ModbusShape ofStream(List<ModbusFrame> frames) {
        boolean sawRequest = false;
        boolean sawResponse = false;

        for (ModbusFrame frame : frames) {
            switch (of(frame.functionCode(), frame.pdu())) {
                case REQUEST_ONLY -> sawRequest = true;
                case RESPONSE_ONLY -> sawResponse = true;
                case UNKNOWN -> { }
            }
        }

        if (sawRequest == sawResponse) {
            return UNKNOWN;  // 둘 다이거나(충돌) 아무것도 아니거나(빈 목록·전부 UNKNOWN)
        }
        return sawRequest ? REQUEST_ONLY : RESPONSE_ONLY;
    }

    private static ModbusShape registerRead(byte[] pdu) {
        if (pdu.length == 4) {
            return REQUEST_ONLY;
        }
        // 응답 바이트수는 2×수량이라 항상 짝수 → 응답 길이는 항상 홀수이고 4 와 겹치지 않는다.
        if (pdu.length >= 1 && pdu.length == 1 + u(pdu[0]) && u(pdu[0]) % 2 == 0) {
            return RESPONSE_ONLY;
        }
        return UNKNOWN;
    }

    private static ModbusShape bitRead(byte[] pdu) {
        // 코일 응답의 바이트수는 홀수도 가능하다(17~24개 코일 → 3바이트). 그때 응답도 4바이트라
        // 요청과 겹치므로 어느 쪽으로도 단정하지 않는다.
        if (pdu.length == 4) {
            return u(pdu[0]) == 3 ? UNKNOWN : REQUEST_ONLY;
        }
        if (pdu.length >= 1 && pdu.length == 1 + u(pdu[0])) {
            return RESPONSE_ONLY;
        }
        return UNKNOWN;
    }

    private static ModbusShape multiWrite(byte[] pdu) {
        if (pdu.length == 4) {
            return RESPONSE_ONLY;  // 주소2 + 수량2, 가변 필드가 없다
        }
        // 최소 6 은 FC 15 의 코일 1개 쓰기(바이트수 1). pdu[4] 를 보기 전에 길이를 먼저 본다.
        if (pdu.length >= 6 && pdu.length == 5 + u(pdu[4])) {
            return REQUEST_ONLY;
        }
        return UNKNOWN;
    }

    /**
     * 바이트수 필드는 250까지 간다. {@code & 0xFF} 를 빠뜨리면 레지스터 123개를 쓰는 FC 16
     * 요청이 {@code 5 + (-10)} 이 되어 이 태스크가 존재하는 이유인 경로에서 신호가 침묵한다.
     */
    private static int u(int b) {
        return b & 0xFF;
    }
}
