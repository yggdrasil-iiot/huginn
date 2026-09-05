package dev.krillin.huginn.decode;

import dev.krillin.huginn.reconcile.Access;

import java.util.Map;

/**
 * Modbus 함수코드를 {@link Access} 로 옮긴다.
 * <p>표로 두는 것은 <b>이 목록 자체가 문서</b>이기 때문이다 — switch 로 흩어놓으면 무엇이 빠졌는지
 * 읽어낼 수 없다. 2차의 S7comm 도 같은 형태를 재사용한다.
 * <p>표에 없는 함수코드는 전부 {@link Access#UNDECIDABLE} 이다. 모르는 것을 READ 로 치면
 * 우회를 놓치고, CONTROL 로 치면 정상 통신이 최고 심각도로 올라간다.
 */
public final class ModbusAccess {

    private static final Map<Integer, Access> BY_FUNCTION_CODE = Map.ofEntries(
        Map.entry(1, Access.READ),    // Read Coils
        Map.entry(2, Access.READ),    // Read Discrete Inputs
        Map.entry(3, Access.READ),    // Read Holding Registers
        Map.entry(4, Access.READ),    // Read Input Registers
        Map.entry(7, Access.READ),    // Read Exception Status
        Map.entry(11, Access.READ),   // Get Comm Event Counter
        Map.entry(12, Access.READ),   // Get Comm Event Log
        Map.entry(17, Access.READ),   // Report Server ID
        Map.entry(20, Access.READ),   // Read File Record
        Map.entry(24, Access.READ),   // Read FIFO Queue

        Map.entry(5, Access.WRITE),   // Write Single Coil
        Map.entry(6, Access.WRITE),   // Write Single Register
        Map.entry(15, Access.WRITE),  // Write Multiple Coils
        Map.entry(16, Access.WRITE),  // Write Multiple Registers
        Map.entry(21, Access.WRITE),  // Write File Record
        Map.entry(22, Access.WRITE),  // Mask Write Register
        Map.entry(23, Access.WRITE),  // Read/Write Multiple Registers — 쓰기가 섞이면 쓰기다

        // Diagnostics. 서브함수 대부분은 카운터 읽기지만 Restart Communications ·
        // Force Listen Only 가 같은 코드에 있어 보수적으로 올린다.
        Map.entry(8, Access.CONTROL),

        // Encapsulated Interface Transport. 함수코드만으로는 정할 수 없다 —
        // MEI Type 을 보고 of(int, byte[]) 가 판정한다. 이 표의 값은 MEI 를 못 읽었을 때의 기본값이다.
        Map.entry(43, Access.UNDECIDABLE));

    private ModbusAccess() {
    }

    /** Encapsulated Interface Transport. 의미가 함수코드가 아니라 MEI Type 에 있다. */
    private static final int ENCAPSULATED_INTERFACE = 43;

    /** Read Device Identification — 장치 식별 정보를 <b>읽기만</b> 한다. */
    private static final int MEI_READ_DEVICE_ID = 0x0E;

    /**
     * @param pdu 함수코드를 뺀 나머지 데이터. FC 43 에서만 본다 — 그 코드의 접근 유형은
     *            함수코드가 아니라 첫 바이트의 MEI Type 이 정하기 때문이다
     */
    public static Access of(int functionCode, byte[] pdu) {
        if (functionCode == ENCAPSULATED_INTERFACE) {
            return encapsulated(pdu);
        }
        return BY_FUNCTION_CODE.getOrDefault(functionCode, Access.UNDECIDABLE);
    }

    /**
     * MEI 14(Read Device Identification)만 읽기로 친다.
     *
     * <p>MEI 13(CANopen General Reference)은 <b>읽기·쓰기를 모두 실어 나르므로</b> 더 파고들지
     * 않는 한 단정할 수 없다. 1차가 FC 43 전체를 UNDECIDABLE 로 둔 판단은 폐기된 것이 아니라
     * <b>적용 범위가 여기로 좁아진 것</b>이다. MEI 를 못 읽어도 지어내지 않는다.
     */
    private static Access encapsulated(byte[] pdu) {
        if (pdu.length == 0) {
            return Access.UNDECIDABLE;
        }
        return (pdu[0] & 0xFF) == MEI_READ_DEVICE_ID ? Access.READ : Access.UNDECIDABLE;
    }
}
