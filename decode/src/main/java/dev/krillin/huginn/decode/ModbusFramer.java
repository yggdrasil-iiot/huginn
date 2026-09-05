package dev.krillin.huginn.decode;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * TCP 스트림 바이트를 MBAP 프레임으로 자른다.
 * <p><b>포트를 인자로 받지 않는다</b> — 502 라는 관례는 거울상 대화를 구별하지 못하므로
 * 프레이밍 자체가 유일한 판정 근거다.
 * <p><b>재동기화하지 않는다.</b> 오프셋 0부터 읽다가 첫 무효 지점에서 멈추고 그 뒤 잔여를
 * 전부 미해독으로 센다. 경계를 찾아 앞으로 스캔하면 임의 바이너리가 Modbus 로 오인되고,
 * 미등록 쌍에서 HIGH Finding 이 만들어진다 — 오탐이 오검출보다 비싸다.
 */
public final class ModbusFramer {

    /** 트랜잭션ID(2) · 프로토콜ID(2) · 길이(2). 다음 프레임 시작 = 오프셋 + 이것 + length. */
    private static final int MBAP_HEADER = 6;

    /** MBAP 6 + 유닛ID 1 + 함수코드 1. 이보다 짧으면 판정 자체가 불가능하다. */
    private static final int MIN_FRAME = 8;

    /** length = 유닛ID(1) + PDU 이고 최소 PDU 는 함수코드 1바이트다. */
    private static final int MIN_LENGTH = 2;

    /** 최대 ADU 260 = MBAP 6 + 유닛 1 + PDU 253. */
    private static final int MAX_LENGTH = 254;

    private ModbusFramer() {
    }

    public static FramingResult frames(byte[] stream) {
        List<ModbusFrame> frames = new ArrayList<>();
        int offset = 0;

        while (stream.length - offset >= MIN_FRAME) {
            int protocolId = u16(stream, offset + 2);
            int length = u16(stream, offset + 4);
            int functionCode = stream[offset + 7] & 0xFF;

            if (protocolId != 0 || length < MIN_LENGTH || length > MAX_LENGTH || functionCode == 0) {
                break;
            }
            int frameSize = MBAP_HEADER + length;
            if (stream.length - offset < frameSize) {
                break;
            }

            frames.add(new ModbusFrame(
                u16(stream, offset),
                stream[offset + 6] & 0xFF,
                functionCode,
                Arrays.copyOfRange(stream, offset + MIN_FRAME, offset + frameSize)));
            offset += frameSize;
        }

        return new FramingResult(List.copyOf(frames), stream.length - offset, !frames.isEmpty());
    }

    private static int u16(byte[] bytes, int offset) {
        return ((bytes[offset] & 0xFF) << 8) | (bytes[offset + 1] & 0xFF);
    }
}
