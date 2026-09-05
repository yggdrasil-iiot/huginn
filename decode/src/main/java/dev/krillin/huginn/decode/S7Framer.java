package dev.krillin.huginn.decode;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * TCP 스트림 바이트를 S7comm 프레임으로 자른다 — TPKT → COTP → S7 의 3중 프레이밍이다.
 *
 * <pre>
 * TPKT   03 00 &lt;len:2&gt;                     len 은 TPKT 헤더 4바이트를 포함한 전체 길이
 * COTP   &lt;li:1&gt; F0 &lt;tpdu-nr|eot:1&gt;         DT Data. eot = 최상위 비트. COTP 헤더 길이 = li + 1
 * S7     32 &lt;rosctr:1&gt; &lt;redundancy:2&gt; &lt;pdu-ref:2&gt; &lt;param-len:2&gt; &lt;data-len:2&gt;
 *        (ROSCTR 2·3 은 오류 클래스·코드 2바이트가 더 붙어 헤더가 12바이트)
 * </pre>
 *
 * <p><b>길이 정합성이 MBAP length 검사에 대응하는 반증 장치다</b> —
 * {@code TPKT len == 4 + (li+1) + 헤더길이 + param-len + data-len} 이 성립해야 유효 프레임이다.
 *
 * <p><b>비-S7 TPKT 는 소비하되 세지 않는다.</b> 실제 클라이언트 스트림은 대개 COTP 연결 요청(CR)으로
 * 시작하므로, 거기서 멈추면 프레임 수가 0 이 되어 그 대화가 통째로 대상 외로 떨어진다.
 * 소비한 프레임은 {@code undecodedBytes} 에도 넣지 않는다 — 미해독 바이트가 아니라 관심사가
 * 아닌 프레임이며, 세면 CR/CC 만 오간 대화에 근거 없는 꼬리 UNDECIDABLE 이 붙는다.
 *
 * <p><b>이것은 재동기화가 아니다.</b> 재동기화는 경계를 찾아 앞으로 스캔하는 것이고, 여기서는
 * TPKT 가 선언한 길이를 따라갈 뿐이다. 1차가 거부한 것은 앞의 것이다.
 *
 * <p><b>포트를 인자로 받지 않는다</b> — 102 라는 관례는 502 와 같은 이유로 쓰지 않는다.
 */
public final class S7Framer {

    /** TPKT 4 + COTP 최소 3. 이보다 짧으면 판정 자체가 불가능하다. */
    private static final int MIN_FRAME = 7;

    /** 0x32. 이것까지 봐야 S7 이다 — TPKT/COTP 는 ISO-on-TCP 일반 규약이다. */
    private static final int S7_PROTOCOL_ID = 0x32;

    /** COTP DT Data. 연결 설정(CR 0xE0·CC 0xD0)은 S7 을 싣지 않는다. */
    private static final int COTP_DATA = 0xF0;

    /** ROSCTR 1·7 은 10바이트, 2·3 은 오류 2바이트가 붙어 12바이트다. */
    private static final int S7_HEADER = 10;
    private static final int S7_HEADER_WITH_ERROR = 12;

    private S7Framer() {
    }

    public static S7FramingResult frames(byte[] stream) {
        List<S7Frame> frames = new ArrayList<>();
        int offset = 0;
        boolean fragmented = false;

        while (stream.length - offset >= MIN_FRAME) {
            if ((stream[offset] & 0xFF) != 0x03 || (stream[offset + 1] & 0xFF) != 0x00) {
                break;                                  // TPKT 매직이 아니다
            }
            int length = u16(stream, offset + 2);
            if (length < MIN_FRAME || stream.length - offset < length) {
                break;                                  // 길이가 비정상이거나 절단됐다
            }

            int cotpHeader = (stream[offset + 4] & 0xFF) + 1;
            if (cotpHeader < 3 || 4 + cotpHeader > length) {
                break;                                  // COTP 헤더가 프레임 밖으로 나간다
            }
            if ((stream[offset + 5] & 0xFF) != COTP_DATA) {
                offset += length;                       // 연결 설정 등 — 소비하되 세지 않는다
                continue;
            }
            if ((stream[offset + 6] & 0x80) == 0) {
                fragmented = true;                      // EOT 가 꺼졌다. 재조립하지 않는다
                break;
            }

            int payload = offset + 4 + cotpHeader;
            int payloadLength = length - 4 - cotpHeader;
            if (payloadLength < S7_HEADER || (stream[payload] & 0xFF) != S7_PROTOCOL_ID) {
                offset += length;                       // S7 이 아니다 — 소비하되 세지 않는다
                continue;
            }

            int rosctr = stream[payload + 1] & 0xFF;
            int header = (rosctr == 2 || rosctr == 3) ? S7_HEADER_WITH_ERROR : S7_HEADER;
            if (payloadLength < header) {
                offset += length;
                continue;
            }
            int parameterLength = u16(stream, payload + 6);
            int dataLength = u16(stream, payload + 8);
            if (length != 4 + cotpHeader + header + parameterLength + dataLength) {
                break;                                  // 길이 정합성이 깨졌다
            }

            frames.add(new S7Frame(rosctr,
                Arrays.copyOfRange(stream, payload + header, payload + header + parameterLength)));
            offset += length;
        }

        return new S7FramingResult(List.copyOf(frames), stream.length - offset, fragmented);
    }

    private static int u16(byte[] bytes, int offset) {
        return ((bytes[offset] & 0xFF) << 8) | (bytes[offset + 1] & 0xFF);
    }
}
