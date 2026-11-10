package yggdrasil.huginn.zeek;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Huginn 이 읽는 세 로그와 각자 반드시 있어야 하는 열·타입.
 *
 * <p>ICSNPP 는 태그한 릴리스가 없다. 그래서 무엇에 맞춰 짰는지를 <b>커밋 해시로</b> 적는다 —
 * cisagov/icsnpp-s7comm 102a35c(2026-10-22), cisagov/icsnpp-modbus 6dd3dab(2026-10-17),
 * Zeek 9.0.1. 쓰는 열이 사라지거나 타입이 바뀌면 의미가 바뀐 것일 수 있으므로 거부한다.
 * 열 순서가 바뀌거나 열이 늘어난 것은 받는다 — 이름으로 읽기 때문이다.
 */
final class ZeekSchema {

    static final String S7COMM = "s7comm";
    static final String S7COMM_PLUS = "s7comm_plus";
    static final String MODBUS_DETAILED = "modbus_detailed";

    private static final Map<String, Map<String, String>> REQUIRED = Map.of(
        S7COMM, ordered(
            "ts", "time",
            "source_h", "addr", "source_p", "port",
            "destination_h", "addr", "destination_p", "port",
            "rosctr_code", "count",
            "function_code", "string", "function_name", "string",
            "subfunction_name", "string"),
        S7COMM_PLUS, ordered(
            "ts", "time",
            "source_h", "addr", "source_p", "port",
            "destination_h", "addr", "destination_p", "port",
            "opcode", "string",
            "function_code", "string", "function_name", "string"),
        MODBUS_DETAILED, ordered(
            "ts", "time", "uid", "string",
            "id.orig_h", "addr", "id.orig_p", "port",
            "id.resp_h", "addr", "id.resp_p", "port",
            "tid", "count", "unit", "count", "func", "string",
            "address", "count", "quantity", "count",
            "request_values", "vector[count]",
            "matched", "bool",
            "request_subfunction_code", "string", "request_data", "string",
            "exception_code", "string", "mei_type", "string"));

    private ZeekSchema() {
    }

    static boolean supports(String path) {
        return REQUIRED.containsKey(path);
    }

    static String supported() {
        return String.join(", ", REQUIRED.keySet().stream().sorted().toList());
    }

    /** 이 {@code #path} 가 요구하는 열 → 타입. */
    static Map<String, String> required(String path) {
        return REQUIRED.get(path);
    }

    private static Map<String, String> ordered(String... pairs) {
        Map<String, String> out = new LinkedHashMap<>();
        for (int i = 0; i < pairs.length; i += 2) {
            out.put(pairs[i], pairs[i + 1]);
        }
        return out;
    }
}
