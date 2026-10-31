package dev.krillin.huginn.zeek;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static dev.krillin.huginn.zeek.ZeekLogs.MODBUS_FIELDS;
import static dev.krillin.huginn.zeek.ZeekLogs.MODBUS_TYPES;
import static dev.krillin.huginn.zeek.ZeekLogs.S7COMM_FIELDS;
import static dev.krillin.huginn.zeek.ZeekLogs.S7COMM_TYPES;
import static dev.krillin.huginn.zeek.ZeekLogs.log;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ZeekLogReaderTest {

    private static final String JOB_ROW = ZeekLogs.row("1700000000.5", "C1", "10.0.0.1", 50000,
        "10.0.0.2", 102, "T", "10.0.0.1", 50000, "10.0.0.2", 102, 1, "Job-Request", 0, "0x04",
        "Read Variable", "-", "-", "-", "-");

    private static String rejected(String text) {
        return assertThrows(ZeekLogException.class, () -> ZeekLogReader.parse(text, "t.log")).getMessage();
    }

    @Test
    void 헤더를_읽고_행을_이름으로_펼친다() {
        ZeekLog log = ZeekLogReader.parse(ZeekLogs.s7comm(JOB_ROW), "t.log");

        assertEquals("s7comm", log.path());
        assertEquals(1, log.rows().size());
        ZeekLog.Row row = log.rows().get(0);
        assertEquals(9, row.line(), "헤더 여덟 줄 다음이다");
        assertEquals("0x04", row.get("function_code"));
        assertNull(row.get("subfunction_name"), "unset(-)은 null 이다");
    }

    @Test
    void unset_과_empty_는_다르다() {
        String row = JOB_ROW.replace("Read Variable", "(empty)");
        ZeekLog.Row parsed = ZeekLogReader.parse(ZeekLogs.s7comm(row), "t.log").rows().get(0);

        assertEquals("", parsed.get("function_name"));
        assertNull(parsed.get("error_code"));
    }

    @Test
    void 헤더가_선언한_표기를_따른다() {
        // 구분자를 쉼표로, unset 을 NA 로 바꿔도 같은 행을 읽어야 한다 — 기본값을 가정하지 않는다.
        String text = ZeekLogs.s7comm(JOB_ROW)
            .replace("#separator \\x09", "#separator \\x2c")
            .replace("\t", ",")
            .replace(",-", ",NA")
            .replace("#unset_field,NA", "#unset_field,NA");
        ZeekLog.Row row = ZeekLogReader.parse(text, "t.log").rows().get(0);

        assertEquals("Read Variable", row.get("function_name"));
        assertNull(row.get("subfunction_name"));
    }

    @Test
    void 이스케이프를_푼다() {
        assertEquals("a\tb", ZeekLogReader.unescape("a\\x09b"));
        assertEquals("a\\b", ZeekLogReader.unescape("a\\\\b"));
        assertEquals("\\x0", ZeekLogReader.unescape("\\x0"), "자리가 모자라면 그대로 둔다");
    }

    @Test
    void 열_순서가_바뀌어도_이름으로_읽는다() {
        List<String> fields = new ArrayList<>(S7COMM_FIELDS);
        List<String> types = new ArrayList<>(S7COMM_TYPES);
        fields.add("extra");
        types.add("string");
        java.util.Collections.swap(fields, 0, 14);
        java.util.Collections.swap(types, 0, 14);
        String[] cells = (JOB_ROW + "\tz").split("\t");
        String swapped = cells[0];
        cells[0] = cells[14];
        cells[14] = swapped;

        ZeekLog.Row row = ZeekLogReader.parse(log("s7comm", fields, types, String.join("\t", cells)), "t.log")
            .rows().get(0);

        assertEquals("0x04", row.get("function_code"));
        assertEquals("1700000000.5", row.get("ts"));
    }

    @Test
    void JSON_은_거부한다() {
        assertTrue(rejected("{\"ts\":1.0,\"uid\":\"C1\"}\n").contains("JSON"));
    }

    @Test
    void 읽지_않는_로그는_거부한다() {
        String conn = log("conn", List.of("ts", "uid"), List.of("time", "string"), "1.0\tC1");
        assertTrue(rejected(conn).contains("#path conn"));
    }

    @Test
    void 쓰는_열이_없으면_거부한다() {
        List<String> fields = new ArrayList<>(S7COMM_FIELDS);
        List<String> types = new ArrayList<>(S7COMM_TYPES);
        int at = fields.indexOf("source_h");
        fields.remove(at);
        types.remove(at);
        assertTrue(rejected(log("s7comm", fields, types)).contains("source_h"));
    }

    @Test
    void 쓰는_열의_타입이_바뀌면_거부한다() {
        List<String> types = new ArrayList<>(MODBUS_TYPES);
        types.set(MODBUS_FIELDS.indexOf("matched"), "string");
        assertTrue(rejected(log("modbus_detailed", MODBUS_FIELDS, types)).contains("matched"));
    }

    @Test
    void 열_수가_다른_행은_거부한다() {
        assertTrue(rejected(ZeekLogs.s7comm(JOB_ROW + "\textra")).contains(":9:"));
    }

    @Test
    void 헤더보다_먼저_온_데이터는_거부한다() {
        assertTrue(rejected(JOB_ROW + "\n" + ZeekLogs.s7comm()).contains("#separator"));
    }

    @Test
    void 헤더가_없으면_거부한다() {
        assertTrue(rejected("").contains("헤더가 없다"));
    }

    @Test
    void 필드와_타입_수가_다르면_거부한다() {
        List<String> types = new ArrayList<>(S7COMM_TYPES);
        types.remove(types.size() - 1);
        assertTrue(rejected(log("s7comm", S7COMM_FIELDS, types)).contains("#types"));
    }

    @Test
    void 열_이름이_겹치면_거부한다() {
        List<String> fields = new ArrayList<>(S7COMM_FIELDS);
        fields.set(fields.indexOf("error_code"), "error_class");
        assertTrue(rejected(log("s7comm", fields, S7COMM_TYPES)).contains("겹친다"));
    }

    @Test
    void 이어_붙인_로그는_묶음마다_검증하고_path_가_섞이면_거부한다() {
        String twice = ZeekLogs.s7comm(JOB_ROW) + ZeekLogs.s7comm(JOB_ROW);
        assertEquals(2, ZeekLogReader.parse(twice, "t.log").rows().size());

        String mixed = ZeekLogs.s7comm(JOB_ROW) + ZeekLogs.modbus();
        assertTrue(rejected(mixed).contains("#path 가 둘"));
    }

    @Test
    void CRLF_와_BOM_을_견딘다() {
        String text = "﻿" + ZeekLogs.s7comm(JOB_ROW).replace("\n", "\r\n");
        assertEquals("Read Variable", ZeekLogReader.parse(text, "t.log").rows().get(0).get("function_name"));
    }
}
