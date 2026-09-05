package dev.krillin.huginn.decode;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static dev.krillin.huginn.decode.ModbusFixtures.concat;
import static dev.krillin.huginn.decode.ModbusFixtures.mbap;
import static dev.krillin.huginn.decode.ModbusFixtures.pdu;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ModbusFramerTest {

    /** 유효 프레임의 protocolId 두 바이트를 덮어쓴다. */
    private byte[] withProtocolId(byte[] frame, int protocolId) {
        byte[] out = frame.clone();
        out[2] = (byte) (protocolId >>> 8);
        out[3] = (byte) protocolId;
        return out;
    }

    /** 유효 프레임의 length 필드만 덮어쓴다 — 실제 바이트 수는 그대로다. */
    private byte[] withLengthField(byte[] frame, int length) {
        byte[] out = frame.clone();
        out[4] = (byte) (length >>> 8);
        out[5] = (byte) length;
        return out;
    }

    /** 유효 프레임의 함수코드를 덮어쓴다. */
    private byte[] withFunctionCode(byte[] frame, int fc) {
        byte[] out = frame.clone();
        out[7] = (byte) fc;
        return out;
    }

    @Test
    void 유효한_MBAP_프레임을_뽑는다() {
        byte[] body = pdu(0, 10);
        FramingResult r = ModbusFramer.frames(mbap(1, 1, 3, body));

        assertTrue(r.isModbusStream());
        assertEquals(0, r.undecodedBytes());
        assertEquals(1, r.frames().size());

        ModbusFrame frame = r.frames().get(0);
        assertEquals(1, frame.transactionId());
        assertEquals(1, frame.unitId());
        assertEquals(3, frame.functionCode());
        assertArrayEquals(body, frame.pdu());
    }

    @Test
    void 한_스트림에_연속된_프레임_여러_개를_뽑는다() {
        // 다음 프레임 시작 = 오프셋 + 6 + length. 7 + length 로 오해하면 두 번째부터 깨진다.
        byte[] stream = concat(
            mbap(1, 1, 3, pdu(0, 10)),
            mbap(2, 1, 6, pdu(7, 1234)),
            mbap(3, 1, 3, pdu(100, 2)));

        FramingResult r = ModbusFramer.frames(stream);

        assertTrue(r.isModbusStream());
        assertEquals(0, r.undecodedBytes());
        assertEquals(3, r.frames().size());
        assertEquals(2, r.frames().get(1).transactionId());
        assertEquals(6, r.frames().get(1).functionCode());
        assertArrayEquals(pdu(7, 1234), r.frames().get(1).pdu());
        assertEquals(3, r.frames().get(2).transactionId());
    }

    @Test
    void protocolId가_0이_아니면_프레임이_아니다() {
        // 포트가 502 여도 — 프레이밍만으로 판정한다.
        byte[] stream = withProtocolId(mbap(1, 1, 3, pdu(0, 10)), 1);

        FramingResult r = ModbusFramer.frames(stream);

        assertFalse(r.isModbusStream());
        assertTrue(r.frames().isEmpty());
        assertEquals(stream.length, r.undecodedBytes());
    }

    @Test
    void 길이_필드가_범위를_벗어나면_프레임이_아니다() {
        // 최대 ADU 260 = MBAP 6 + 유닛 1 + PDU 253 → 상한 254.
        // 하한은 2 다 — length = 유닛ID(1) + PDU 이고 최소 PDU 는 함수코드 1바이트.
        // 1 을 허용하면 함수코드 자리에 다음 프레임의 첫 바이트를 읽는다.
        byte[] valid = mbap(1, 1, 3, pdu(0, 10));

        FramingResult tooSmall = ModbusFramer.frames(withLengthField(valid, 1));
        assertFalse(tooSmall.isModbusStream());
        assertTrue(tooSmall.frames().isEmpty());
        assertEquals(valid.length, tooSmall.undecodedBytes());

        FramingResult tooBig = ModbusFramer.frames(withLengthField(valid, 255));
        assertFalse(tooBig.isModbusStream());
        assertTrue(tooBig.frames().isEmpty());
        assertEquals(valid.length, tooBig.undecodedBytes());

        // 경계값 254 는 프레임이다 — 상한을 253 으로 잡으면 최대 크기 ADU 를 통째로 놓친다.
        byte[] maxSized = mbap(1, 1, 3, new byte[252]);
        FramingResult atUpperBound = ModbusFramer.frames(maxSized);
        assertTrue(atUpperBound.isModbusStream());
        assertEquals(1, atUpperBound.frames().size());
        assertEquals(0, atUpperBound.undecodedBytes());
    }

    @Test
    void 함수코드가_0이면_프레임이_아니다() {
        byte[] stream = withFunctionCode(mbap(1, 1, 3, pdu(0, 10)), 0);

        FramingResult r = ModbusFramer.frames(stream);

        assertFalse(r.isModbusStream());
        assertTrue(r.frames().isEmpty());
        assertEquals(stream.length, r.undecodedBytes());
    }

    @Test
    void 마지막_프레임이_잘려도_예외가_아니라_미해독_바이트다() {
        // 캡처가 프레임 중간에서 끝나는 것은 정상적인 상황이다.
        byte[] first = mbap(1, 1, 3, pdu(0, 10));
        byte[] second = mbap(2, 1, 3, pdu(0, 10));

        // ① 헤더도 못 채운 절단 — 잔여 < 8
        FramingResult headerCut = ModbusFramer.frames(
            concat(first, Arrays.copyOf(second, 5)));
        assertTrue(headerCut.isModbusStream());
        assertEquals(1, headerCut.frames().size());
        assertEquals(5, headerCut.undecodedBytes());

        // ② 헤더는 온전하나 본문이 모자란 절단 — 잔여 < 6 + length
        FramingResult bodyCut = ModbusFramer.frames(
            concat(first, Arrays.copyOf(second, second.length - 2)));
        assertTrue(bodyCut.isModbusStream());
        assertEquals(1, bodyCut.frames().size());
        assertEquals(second.length - 2, bodyCut.undecodedBytes());
    }

    @Test
    void 프레임을_하나도_못_뽑으면_Modbus_스트림이_아니다() {
        // SSH·HTTP 등. UNDECIDABLE 이 아니라 대상 외다 — 설계 §5-⑥.
        FramingResult r = ModbusFramer.frames(
            "SSH-2.0-OpenSSH_9.0\r\n".getBytes(StandardCharsets.US_ASCII));

        assertFalse(r.isModbusStream());
        assertTrue(r.frames().isEmpty());
    }

    @Test
    void 프레임_뒤의_잔여_바이트만_미해독으로_센다() {
        // 재동기화를 하지 않으므로 '프레임 사이' 라는 것은 없다 — 첫 무효 지점 이후의 잔여뿐이다.
        byte[] garbage = "GET / HTTP/1.1\r\n".getBytes(StandardCharsets.US_ASCII);
        byte[] stream = concat(mbap(1, 1, 3, pdu(0, 10)), garbage);

        FramingResult r = ModbusFramer.frames(stream);

        assertTrue(r.isModbusStream());
        assertEquals(1, r.frames().size());
        assertEquals(garbage.length, r.undecodedBytes());
    }

    @Test
    void 스트림_중간부터_시작해도_재동기화하지_않는다() {
        // 프레임 경계를 찾아 앞으로 스캔하지 않는다. 오탐이 오검출보다 비싸다.
        byte[] tailOfPreviousFrame = new byte[] {0x00, 0x03, 0x02, 0x00};
        byte[] stream = concat(tailOfPreviousFrame, mbap(1, 1, 3, pdu(0, 10)));

        FramingResult r = ModbusFramer.frames(stream);

        assertFalse(r.isModbusStream());
        assertTrue(r.frames().isEmpty());
        assertEquals(stream.length, r.undecodedBytes());
    }
}
