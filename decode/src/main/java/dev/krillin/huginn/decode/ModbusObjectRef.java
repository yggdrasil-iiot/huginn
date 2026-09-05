package dev.krillin.huginn.decode;

import java.util.Map;

/**
 * 요청이 건드린 대상을 사람이 읽는 표기로 옮긴다 — 예: {@code "holding:40001"}.
 * <p>{@code Observation.objectRef} 는 <b>근거 표시용이며 판정에는 쓰지 않는다.</b> 그래도 이것이
 * 없으면 리포트를 받은 운영자가 무엇을 조치해야 하는지 알 수 없다.
 * <p>표기는 관례적인 데이터 모델 번호를 따른다 — 와이어 주소 0 이 1번이고, 이산 입력은 10001,
 * 입력 레지스터는 30001, 홀딩 레지스터는 40001 에서 시작한다.
 * <p>주소를 읽을 수 없으면(PDU 에 주소가 없거나 잘렸으면) 지어내지 않고 {@code "fc:<n>"} 으로 적는다.
 */
public final class ModbusObjectRef {

    private record ObjectKind(String name, int base) {
    }

    private static final Map<Integer, ObjectKind> BY_FUNCTION_CODE = Map.of(
        1, new ObjectKind("coil", 1),          // Read Coils
        5, new ObjectKind("coil", 1),          // Write Single Coil
        15, new ObjectKind("coil", 1),         // Write Multiple Coils
        2, new ObjectKind("discrete", 10001),  // Read Discrete Inputs
        4, new ObjectKind("input", 30001),     // Read Input Registers
        3, new ObjectKind("holding", 40001),   // Read Holding Registers
        6, new ObjectKind("holding", 40001),   // Write Single Register
        16, new ObjectKind("holding", 40001),  // Write Multiple Registers
        22, new ObjectKind("holding", 40001),  // Mask Write Register
        23, new ObjectKind("holding", 40001)); // Read/Write Multiple Registers — 읽기 시작 주소

    private ModbusObjectRef() {
    }

    /**
     * @param pdu 함수코드를 뺀 나머지 데이터. 앞 2바이트가 시작 주소인 함수코드에서만 쓰인다.
     */
    public static String of(int functionCode, byte[] pdu) {
        if (functionCode == 43) {
            return encapsulated(pdu);
        }
        ObjectKind kind = BY_FUNCTION_CODE.get(functionCode);
        if (kind == null || pdu.length < 2) {
            return "fc:" + functionCode;
        }
        int startAddress = ((pdu[0] & 0xFF) << 8) | (pdu[1] & 0xFF);
        return kind.name() + ":" + (kind.base() + startAddress);
    }

    /**
     * FC 43 은 주소가 아니라 MEI 구조를 싣는다. MEI 14 면 Read Device ID 코드까지 적는다 —
     * tshark 의 {@code modbus.read_device_id} 와 대조되는 값이며 실캡처에 코드 1·2 가 나타난다.
     * 그 외 MEI 는 무엇을 건드렸는지 모르므로 함수코드만 적는다.
     */
    private static String encapsulated(byte[] pdu) {
        if (pdu.length >= 2 && (pdu[0] & 0xFF) == 0x0E) {
            return "device-id:" + (pdu[1] & 0xFF);
        }
        return "fc:43";
    }
}
