package dev.krillin.huginn.decode;

/**
 * MBAP 헤더에서 뽑아낸 Modbus/TCP 프레임 하나.
 *
 * @param pdu 함수코드를 <b>뺀</b> 나머지 데이터. 따라서 {@code pdu.length == length - 2} 다.
 */
public record ModbusFrame(int transactionId, int unitId, int functionCode, byte[] pdu) {
}
