package dev.krillin.huginn.decode;

import org.junit.jupiter.api.Test;

import static dev.krillin.huginn.decode.ModbusFixtures.pdu;
import static org.junit.jupiter.api.Assertions.assertEquals;

class ModbusObjectRefTest {

    @Test
    void 코일_읽기는_코일_주소로_표기한다() {
        // FC 1, 시작 주소 0 → "coil:1"  (와이어 주소 0 이 1번 코일)
        assertEquals("coil:1", ModbusObjectRef.of(1, pdu(0x0000, 0x0008)));
    }

    @Test
    void 홀딩_레지스터_읽기는_4만번대로_표기한다() {
        // FC 3, 시작 주소 0 → "holding:40001"
        assertEquals("holding:40001", ModbusObjectRef.of(3, pdu(0x0000, 0x0002)));
    }

    @Test
    void 입력_레지스터는_3만번대다() {
        assertEquals("input:30010", ModbusObjectRef.of(4, pdu(9, 1)));
    }

    @Test
    void 이산_입력은_1만번대다() {
        assertEquals("discrete:10005", ModbusObjectRef.of(2, pdu(4, 1)));
    }

    @Test
    void 단일_쓰기도_같은_규칙이다() {
        assertEquals("holding:40100", ModbusObjectRef.of(6, pdu(99, 1)));
    }

    @Test
    void 시작_주소를_읽을_수_없는_함수코드는_함수코드만_적는다() {
        // FC 8(진단), 43(캡슐화) 등은 PDU 에 주소가 없다.
        assertEquals("fc:8", ModbusObjectRef.of(8, new byte[]{0x00, 0x00}));
    }

    @Test
    void PDU가_짧아_주소를_못_읽으면_함수코드만_적는다() {
        assertEquals("fc:3", ModbusObjectRef.of(3, new byte[]{0x00}));
    }
}
