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

        // Encapsulated Interface Transport. 의미는 MEI Type 이 정한다 — MEI 14 는 읽기,
        // MEI 13(CANopen)은 읽기·쓰기를 모두 실어 나른다. MEI 를 보지 않고 단정하지 않는다.
        Map.entry(43, Access.UNDECIDABLE));

    private ModbusAccess() {
    }

    public static Access of(int functionCode) {
        return BY_FUNCTION_CODE.getOrDefault(functionCode, Access.UNDECIDABLE);
    }
}
