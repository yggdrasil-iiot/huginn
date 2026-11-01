package dev.krillin.huginn.zeek;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 시험용 Zeek 로그. 헤더를 손으로 쓰면 탭 하나 틀려도 시험이 엉뚱한 이유로 실패한다.
 *
 * <p>{@link #icsnpp(String)} 는 커밋된 ICSNPP 기준 로그를 읽는다. 그 파일은 btest 가 {@code ts} 를
 * {@code XXXXXXXXXX.XXXXXX} 로 가려 두었으므로 <b>메모리에서만</b> 행마다 다른 시각으로 바꾼다 —
 * 커밋된 파일은 원본 그대로이고, 운영 코드는 가린 시각을 거부한다.
 */
public final class ZeekLogs {

    static final List<String> S7COMM_FIELDS = List.of(
        "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "is_orig",
        "source_h", "source_p", "destination_h", "destination_p", "rosctr_code", "rosctr_name",
        "pdu_reference", "function_code", "function_name", "subfunction_code", "subfunction_name",
        "error_class", "error_code");
    static final List<String> S7COMM_TYPES = List.of(
        "time", "string", "addr", "port", "addr", "port", "bool", "addr", "port", "addr", "port",
        "count", "string", "count", "string", "string", "string", "string", "string", "string");

    static final List<String> S7COMM_PLUS_FIELDS = List.of(
        "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "is_orig",
        "source_h", "source_p", "destination_h", "destination_p", "version", "opcode", "opcode_name",
        "function_code", "function_name");
    static final List<String> S7COMM_PLUS_TYPES = List.of(
        "time", "string", "addr", "port", "addr", "port", "bool", "addr", "port", "addr", "port",
        "count", "string", "string", "string", "string");

    static final List<String> MODBUS_FIELDS = List.of(
        "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "tid", "unit", "func",
        "address", "quantity", "request_values", "response_values", "modbus_detailed_link_id",
        "matched", "request_subfunction_code", "response_subfunction_code", "request_data",
        "response_data", "exception_code", "mei_type");
    static final List<String> MODBUS_TYPES = List.of(
        "time", "string", "addr", "port", "addr", "port", "count", "count", "string",
        "count", "count", "vector[count]", "vector[count]", "string",
        "bool", "string", "string", "string", "string", "string", "string");

    private ZeekLogs() {
    }

    /** 표준 헤더 + 행. 행은 탭으로 이은 문자열이다. */
    static String log(String path, List<String> fields, List<String> types, String... rows) {
        StringBuilder out = new StringBuilder()
            .append("#separator \\x09\n")
            .append("#set_separator\t,\n")
            .append("#empty_field\t(empty)\n")
            .append("#unset_field\t-\n")
            .append("#path\t").append(path).append('\n')
            .append("#open\t2026-11-01-00-00-00\n")
            .append("#fields\t").append(String.join("\t", fields)).append('\n')
            .append("#types\t").append(String.join("\t", types)).append('\n');
        for (String row : rows) {
            out.append(row).append('\n');
        }
        return out.append("#close\t2026-11-01-00-00-01\n").toString();
    }

    static String s7comm(String... rows) {
        return log("s7comm", S7COMM_FIELDS, S7COMM_TYPES, rows);
    }

    static String s7commPlus(String... rows) {
        return log("s7comm_plus", S7COMM_PLUS_FIELDS, S7COMM_PLUS_TYPES, rows);
    }

    static String modbus(String... rows) {
        return log("modbus_detailed", MODBUS_FIELDS, MODBUS_TYPES, rows);
    }

    /** 탭으로 잇는다. */
    static String row(Object... values) {
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < values.length; i++) {
            if (i > 0) {
                out.append('\t');
            }
            out.append(values[i]);
        }
        return out.toString();
    }

    private static final Pattern MASKED_TS = Pattern.compile("^XXXXXXXXXX\\.XXXXXX", Pattern.MULTILINE);

    /** 커밋된 ICSNPP 기준 로그 원문. */
    public static String icsnppRaw(String resource) {
        try (InputStream in = ZeekLogs.class.getResourceAsStream("/icsnpp/" + resource)) {
            if (in == null) {
                throw new IllegalArgumentException("픽스처 없음: " + resource);
            }
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    /** btest 가 맨 앞에 붙인 안내 줄. Zeek 출력이 아니므로 메모리에서 뗀다. */
    private static final Pattern BTEST_BANNER = Pattern.compile("\\A### BTest baseline data[^\n]*\n");

    /** btest 안내 줄을 떼고 가린 {@code ts} 를 1초 간격의 시각으로 바꾼 기준 로그. */
    public static String icsnpp(String resource) {
        String zeekOutput = BTEST_BANNER.matcher(icsnppRaw(resource)).replaceFirst("");
        Matcher m = MASKED_TS.matcher(zeekOutput);
        StringBuilder out = new StringBuilder();
        int n = 0;
        while (m.find()) {
            m.appendReplacement(out, (1_700_000_000L + n++) + ".000000");
        }
        m.appendTail(out);
        return out.toString();
    }
}
