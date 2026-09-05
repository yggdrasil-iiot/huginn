package dev.krillin.huginn.decode;

import java.util.Locale;

/**
 * 요청이 건드린 대상을 사람이 읽는 표기로 옮긴다 — 예: {@code "sym:m/16"} · {@code "db1.dbx20.0"}.
 *
 * <p>{@code Observation.objectRef} 는 <b>근거 표시용이며 판정에는 쓰지 않는다.</b> 그래도 이것이
 * 없으면 리포트를 받은 운영자가 무엇을 조치해야 하는지 알 수 없다.
 *
 * <p><b>실캡처의 주소는 100% 가 1200SYM 이고 교과서의 S7ANY 는 0건이다</b>(4SICS 세 캡처).
 * 둘 다 다루되 검증 강도가 다르며, 그 사실을 문서에 적는다.
 *
 * <p>어느 쪽도 못 읽으면 지어내지 않고 {@code "fc:<n>"} 으로 적는다 — 1차 {@link ModbusObjectRef}
 * 와 같은 원칙이다.
 */
public final class S7ObjectRef {

    private static final int READ_VAR = 0x04;
    private static final int WRITE_VAR = 0x05;
    private static final int SYNTAX_S7ANY = 0x10;
    private static final int SYNTAX_1200SYM = 0xB2;

    /** 1200SYM 항목에서 LID 앞까지: syntax id(1) + reserved(1) + area1(2) + area2(2) + CRC(4). */
    private static final int SYM_PREFIX = 10;

    /** 이름을 아는 root area 는 이것 하나뿐이다 — 실캡처에 나타난 유일한 값이다. */
    private static final int AREA2_FLAGS = 0x0052;

    private S7ObjectRef() {
    }

    /** @param parameter 프레임의 파라미터 전체(함수코드부터). 함수코드만 넘기면 주소를 찾을 수 없다. */
    public static String of(byte[] parameter) {
        if (parameter.length < 2) {
            return functionOnly(parameter);
        }
        int function = parameter[0] & 0xFF;
        if (function != READ_VAR && function != WRITE_VAR) {
            return functionOnly(parameter);
        }

        int itemCount = parameter[1] & 0xFF;
        String suffix = itemCount > 1 ? " (+" + (itemCount - 1) + ")" : "";
        String first = firstItem(parameter);
        return (first != null ? first : functionOnly(parameter)) + suffix;
    }

    /** 첫 항목만 읽는다. 읽을 수 없으면 null 이다 — 항목 수 표기는 그래도 붙는다. */
    private static String firstItem(byte[] parameter) {
        if (parameter.length < 4 || (parameter[2] & 0xFF) != 0x12) {
            return null;
        }
        int length = parameter[3] & 0xFF;
        int body = 4;
        if (parameter.length < body + length || length < 1) {
            return null;
        }

        int syntaxId = parameter[body] & 0xFF;
        if (syntaxId == SYNTAX_1200SYM) {
            return sym(parameter, body, length);
        }
        if (syntaxId == SYNTAX_S7ANY) {
            return s7any(parameter, body, length);
        }
        return null;
    }

    /** {@code b2 <reserved:1> <area1:2> <area2:2> <crc:4> <lid:4>*} — LID 개수는 {@code (len-10)/4} 다. */
    private static String sym(byte[] parameter, int body, int length) {
        if (length < SYM_PREFIX) {
            return null;
        }
        int area1 = u16(parameter, body + 2);
        int area2 = u16(parameter, body + 4);

        StringBuilder out = new StringBuilder("sym:");
        if (area1 == 0x0000 && area2 == AREA2_FLAGS) {
            out.append('m');
        } else {
            // area1 이 0 이 아니면 area2 는 영역 코드가 아니라 DB 번호 계열이다. 지어내지 않는다.
            out.append(String.format(Locale.ROOT, "0x%04x:0x%04x", area1, area2));
        }

        int lidCount = (length - SYM_PREFIX) / 4;
        for (int i = 0; i < lidCount; i++) {
            int at = body + SYM_PREFIX + i * 4;
            // 상위 4비트는 LID 플래그다. 주소는 하위 28비트.
            long lid = ((long) (parameter[at] & 0x0F) << 24)
                | ((parameter[at + 1] & 0xFF) << 16)
                | ((parameter[at + 2] & 0xFF) << 8)
                | (parameter[at + 3] & 0xFF);
            out.append('/').append(lid);
        }
        return out.toString();
    }

    /** {@code 10 <transport:1> <length:2> <db:2> <area:1> <address:3>} — 관례적인 영역 표기로 옮긴다. */
    private static String s7any(byte[] parameter, int body, int length) {
        if (length < SYM_PREFIX) {
            return null;
        }
        int dbNumber = u16(parameter, body + 4);
        int area = parameter[body + 6] & 0xFF;
        int bitAddress = ((parameter[body + 7] & 0xFF) << 16)
            | ((parameter[body + 8] & 0xFF) << 8)
            | (parameter[body + 9] & 0xFF);
        int byteAddress = bitAddress / 8;
        int bit = bitAddress % 8;

        return switch (area) {
            case 0x84 -> "db" + dbNumber + ".dbx" + byteAddress + "." + bit;
            case 0x83 -> "m" + byteAddress + "." + bit;
            case 0x81 -> "i" + byteAddress + "." + bit;
            case 0x82 -> "q" + byteAddress + "." + bit;
            case 0x1C -> "c" + byteAddress;    // 카운터·타이머는 비트 주소가 없다
            case 0x1D -> "t" + byteAddress;
            default -> null;
        };
    }

    /** {@code parameter[0] & 0xFF} — 부호 있는 byte 로 쓰면 0xF0 이 -16 이 된다. */
    private static String functionOnly(byte[] parameter) {
        return "fc:" + (parameter.length > 0 ? parameter[0] & 0xFF : -1);
    }

    private static int u16(byte[] bytes, int offset) {
        return ((bytes[offset] & 0xFF) << 8) | (bytes[offset + 1] & 0xFF);
    }
}
