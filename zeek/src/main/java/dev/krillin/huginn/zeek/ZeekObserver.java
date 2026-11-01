package dev.krillin.huginn.zeek;

import dev.krillin.huginn.decode.ModbusAccess;
import dev.krillin.huginn.decode.ModbusObjectRef;
import dev.krillin.huginn.decode.S7Access;
import dev.krillin.huginn.decode.S7ObjectRef;
import dev.krillin.huginn.decode.S7PlusAccess;
import dev.krillin.huginn.reconcile.Access;
import dev.krillin.huginn.reconcile.Endpoint;
import dev.krillin.huginn.reconcile.Observation;
import dev.krillin.huginn.reconcile.Protocol;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Zeek ICSNPP 로그 행을 {@link Observation} 으로 옮긴다. 대사는 하지 않는다 — pcap 경로와 같은
 * {@code Reconciler} 가 한다.
 *
 * <p>접근 유형은 <b>decode 의 표를 그대로</b> 쓴다({@link S7Access}·{@link ModbusAccess}·
 * {@link S7PlusAccess}). 같은 요청을 pcap 으로 보든 로그로 보든 판정이 같아야 하기 때문이다.
 * 여기 있는 지식은 로그 형식 — 어느 행이 요청이고 어느 열이 출발지인지 — 뿐이다.
 *
 * <p>{@code at} 은 행의 {@code ts} 다. pcap 경로의 {@code at} 은 방향 스트림의 첫 세그먼트
 * 시각이라 같은 요청이라도 두 경로의 시각은 다르다.
 */
public final class ZeekObserver {

    private ZeekObserver() {
    }

    public static ZeekObservationResult observe(List<ZeekLog> logs) {
        List<Observation> observations = new ArrayList<>();
        List<LogCoverage> byLog = new ArrayList<>();
        for (ZeekLog log : logs) {
            Tally tally = switch (log.path()) {
                case ZeekSchema.S7COMM -> s7comm(log);
                case ZeekSchema.S7COMM_PLUS -> s7commPlus(log);
                case ZeekSchema.MODBUS_DETAILED -> modbusDetailed(log);
                default -> throw new ZeekLogException(log.source() + ": 읽지 않는 로그다: #path " + log.path());
            };
            observations.addAll(tally.observations);
            byLog.add(tally.coverage(log));
        }
        return new ZeekObservationResult(List.copyOf(observations), List.copyOf(byLog));
    }

    // ── s7comm.log ───────────────────────────────────────────────────────────────────────────

    private static final int ROSCTR_JOB = 1;
    private static final int ROSCTR_ACK = 2;
    private static final int ROSCTR_ACK_DATA = 3;
    private static final int ROSCTR_USERDATA = 7;
    private static final int PLC_CONTROL = 0x28;

    /**
     * ROSCTR 1(Job)만 요청이다 — pcap 경로의 {@code S7Decoder} 와 같다. ROSCTR 2·3 은 응답이다.
     *
     * <p>ROSCTR 7(Userdata)은 함수코드 상위 니블이 방향을 말한다(0x4X 요청, 0x8X 응답). 요청이어도
     * <b>UNDECIDABLE</b> 관찰 하나로 남긴다 — pcap 경로가 Userdata 를 해석하지 않으므로 로그 경로도
     * 더 주장하지 않는다. 로그에 함수·서브함수 이름이 있으니 objectRef 에는 적는다.
     */
    private static Tally s7comm(ZeekLog log) {
        Tally tally = new Tally(Protocol.S7COMM);
        for (ZeekLog.Row row : log.rows()) {
            int rosctr = (int) count(row, "rosctr_code", log);
            int function = hex(row.get("function_code"));
            if (rosctr == ROSCTR_JOB) {
                String ref = S7ObjectRef.ofFunction(function);
                if (function == PLC_CONTROL && row.isSet("subfunction_name")) {
                    ref += " (" + row.get("subfunction_name") + ")";
                }
                tally.request(observation(row, log, "source", "destination", Protocol.S7COMM,
                    S7Access.of(function), ref));
            } else if (rosctr == ROSCTR_USERDATA && (function & 0xF0) == 0x40) {
                tally.request(observation(row, log, "source", "destination", Protocol.S7COMM,
                    Access.UNDECIDABLE,
                    "userdata:" + orDash(row.get("function_name")) + "/" + orDash(row.get("subfunction_name"))));
            } else if (rosctr == ROSCTR_ACK || rosctr == ROSCTR_ACK_DATA
                || (rosctr == ROSCTR_USERDATA && (function & 0xF0) == 0x80)) {
                tally.responseRows++;
            } else {
                tally.unresolved(row, log, "source", "destination", row.get("uid"));
            }
        }
        return tally;
    }

    // ── s7comm_plus.log ──────────────────────────────────────────────────────────────────────

    private static final int PLUS_REQUEST = 0x31;
    private static final int PLUS_RESPONSE = 0x32;
    private static final int PLUS_NOTIFICATION = 0x33;

    /** opcode 0x31(Request)만 요청이다. 0x32 응답과 0x33 알림(PLC 가 먼저 보낸다)은 관찰하지 않는다. */
    private static Tally s7commPlus(ZeekLog log) {
        Tally tally = new Tally(Protocol.S7COMM_PLUS);
        for (ZeekLog.Row row : log.rows()) {
            int opcode = hex(row.get("opcode"));
            if (opcode == PLUS_REQUEST) {
                int function = hex(row.get("function_code"));
                String ref = row.isSet("function_name") ? "fn:" + row.get("function_name") : "fc:" + function;
                tally.request(observation(row, log, "source", "destination", Protocol.S7COMM_PLUS,
                    S7PlusAccess.of(function), ref));
            } else if (opcode == PLUS_RESPONSE || opcode == PLUS_NOTIFICATION) {
                tally.responseRows++;
            } else {
                tally.unresolved(row, log, "source", "destination", row.get("uid"));
            }
        }
        return tally;
    }

    // ── modbus_detailed.log ──────────────────────────────────────────────────────────────────

    /**
     * 행 하나가 <b>패킷이 아니라 트랜잭션</b>이다. ICSNPP 는 요청과 응답을 tid 로 짝지어 한 행으로
     * 쓰고({@code matched=T}), 짝을 못 찾은 쪽은 연결이 끝날 때 {@code matched=F} 로 쓴다.
     * 행에 방향 열이 없으므로 출발지는 {@code id.orig_*} — Zeek 의 Modbus 분석기는 요청 이벤트를
     * 연결을 연 쪽에서 낸다.
     *
     * <ul>
     *   <li>{@code matched=T} — 요청을 봤다. 관찰 하나.</li>
     *   <li>{@code matched=F} — 요청 쪽 열(address·quantity·request_*)이 있으면 요청만 본 것이다.
     *       관찰 하나. 없으면 방향을 정할 수 없다.</li>
     *   <li>{@code matched} unset — ICSNPP 가 따로 다루지 않는 함수(FC 7·11·12·17 등)는 메시지마다
     *       헤더만 한 행씩 쓴다. 같은 연결·tid·함수의 연속한 두 행이 요청과 응답 한 쌍이다. 짝이 없는
     *       한 행은 어느 쪽인지 모른다. 예외 응답만 남은 행도 여기로 온다.</li>
     * </ul>
     *
     * <p>방향을 정할 수 없는 행은 관찰을 지어내지 않고 <b>연결(uid)마다 UNDECIDABLE 하나</b>로 남긴다 —
     * pcap 경로에서 한 방향만 잡힌 대화가 남기는 것과 같은 자리다.
     */
    private static Tally modbusDetailed(ZeekLog log) {
        Tally tally = new Tally(Protocol.MODBUS_TCP);
        List<ZeekLog.Row> rows = log.rows();
        int i = 0;
        while (i < rows.size()) {
            ZeekLog.Row row = rows.get(i);
            String matched = row.get("matched");
            if ("T".equals(matched)) {
                tally.request(modbusRequest(row, log));
                i++;
            } else if ("F".equals(matched)) {
                if (hasRequestFields(row)) {
                    tally.request(modbusRequest(row, log));
                } else {
                    tally.unresolved(row, log, "id.orig", "id.resp", row.get("uid"));
                }
                i++;
            } else if (row.isSet("exception_code")) {
                // 짝 없는 예외 응답 — 요청은 있었지만 보지 못했다.
                tally.unresolved(row, log, "id.orig", "id.resp", row.get("uid"));
                i++;
            } else {
                int end = i + 1;
                while (end < rows.size() && headerOnly(rows.get(end)) && sameTransaction(row, rows.get(end))) {
                    end++;
                }
                int run = end - i;
                for (int pair = 0; pair < run / 2; pair++) {
                    tally.request(modbusRequest(rows.get(i + pair * 2), log));
                    tally.requestRows++;   // 두 행이 한 요청이다
                }
                if (run % 2 == 1) {
                    tally.unresolved(rows.get(end - 1), log, "id.orig", "id.resp", row.get("uid"));
                }
                i = end;
            }
        }
        return tally;
    }

    private static boolean headerOnly(ZeekLog.Row row) {
        return !row.isSet("matched") && !row.isSet("exception_code");
    }

    private static boolean sameTransaction(ZeekLog.Row a, ZeekLog.Row b) {
        return Objects.equals(a.get("uid"), b.get("uid")) && Objects.equals(a.get("tid"), b.get("tid"))
            && Objects.equals(a.get("unit"), b.get("unit")) && Objects.equals(a.get("func"), b.get("func"));
    }

    private static boolean hasRequestFields(ZeekLog.Row row) {
        return row.isSet("address") || row.isSet("quantity") || row.isSet("request_values")
            || row.isSet("request_subfunction_code") || row.isSet("request_data");
    }

    private static final String READ_DEVICE_IDENTIFICATION = "Read Device Identification";

    private static Observation modbusRequest(ZeekLog.Row row, ZeekLog log) {
        String func = row.get("func");
        int code = ModbusNames.code(func);
        if (code < 0) {
            return observation(row, log, "id.orig", "id.resp", Protocol.MODBUS_TCP, Access.UNDECIDABLE,
                "func:" + orDash(func));
        }
        byte[] pdu;
        if (code == 43) {
            // MEI 14 만 읽기다. ICSNPP 가 요청·응답의 MEI 가 다르면 "A and B" 로 이어 쓰는데,
            // 그 경우는 정확히 같지 않으므로 UNDECIDABLE 로 남는다.
            pdu = READ_DEVICE_IDENTIFICATION.equals(row.get("mei_type")) ? new byte[]{0x0E} : new byte[0];
        } else if (row.isSet("address")) {
            long address = count(row, "address", log);
            pdu = new byte[]{(byte) (address >> 8), (byte) address};
        } else {
            pdu = new byte[0];
        }
        return observation(row, log, "id.orig", "id.resp", Protocol.MODBUS_TCP,
            ModbusAccess.of(code, pdu), ModbusObjectRef.of(code, pdu));
    }

    // ── 공통 ─────────────────────────────────────────────────────────────────────────────────

    private static Observation observation(ZeekLog.Row row, ZeekLog log, String from, String to,
                                           Protocol protocol, Access access, String objectRef) {
        return new Observation(instant(row, log),
            endpoint(row, log, from), endpoint(row, log, to), protocol, access, objectRef);
    }

    /** {@code source} → {@code source_h}/{@code source_p}, {@code id.orig} → {@code id.orig_h}/{@code id.orig_p}. */
    private static Endpoint endpoint(ZeekLog.Row row, ZeekLog log, String prefix) {
        String host = row.get(prefix + "_h");
        if (host == null || host.isEmpty()) {
            throw new ZeekLogException(log.source() + ":" + row.line() + ": " + prefix + "_h 가 비었다");
        }
        return new Endpoint(host, (int) count(row, prefix + "_p", log));
    }

    private static Instant instant(ZeekLog.Row row, ZeekLog log) {
        String ts = row.get("ts");
        try {
            BigDecimal seconds = new BigDecimal(Objects.requireNonNull(ts));
            long whole = seconds.longValue();
            long nanos = seconds.subtract(BigDecimal.valueOf(whole)).movePointRight(9).longValue();
            return Instant.ofEpochSecond(whole, nanos);
        } catch (NumberFormatException | NullPointerException e) {
            throw new ZeekLogException(log.source() + ":" + row.line() + ": ts 를 읽을 수 없다: " + ts);
        }
    }

    private static long count(ZeekLog.Row row, String field, ZeekLog log) {
        String value = row.get(field);
        try {
            long parsed = Long.parseLong(Objects.requireNonNull(value));
            if (parsed < 0) {
                throw new NumberFormatException();
            }
            return parsed;
        } catch (NumberFormatException | NullPointerException e) {
            throw new ZeekLogException(log.source() + ":" + row.line() + ": " + field + " 를 읽을 수 없다: " + value);
        }
    }

    /** {@code 0x04f2} → 1266. 비었거나 형식이 다르면 -1 이다 — 판정표에서 UNDECIDABLE 로 떨어진다. */
    static int hex(String value) {
        if (value == null || !value.matches("0[xX][0-9a-fA-F]{1,6}")) {
            return -1;
        }
        return Integer.parseInt(value.substring(2), 16);
    }

    private static String orDash(String value) {
        return value == null || value.isEmpty() ? "-" : value;
    }

    /** 한 파일의 집계. 방향 미확정 UNDECIDABLE 은 연결마다 하나만 낸다. */
    private static final class Tally {
        private final Protocol protocol;
        private final List<Observation> observations = new ArrayList<>();
        private final Set<String> unresolvedConnections = new HashSet<>();
        private int rows;
        private int requestRows;
        private int responseRows;
        private int unresolvedRows;

        Tally(Protocol protocol) {
            this.protocol = protocol;
        }

        void request(Observation observation) {
            observations.add(observation);
            requestRows++;
        }

        void unresolved(ZeekLog.Row row, ZeekLog log, String from, String to, String uid) {
            unresolvedRows++;
            String connection = uid != null ? uid
                : row.get(from + "_h") + ":" + row.get(from + "_p") + ">" + row.get(to + "_h") + ":" + row.get(to + "_p");
            if (unresolvedConnections.add(connection)) {
                observations.add(observation(row, log, from, to, protocol, Access.UNDECIDABLE, "-"));
            }
        }

        LogCoverage coverage(ZeekLog log) {
            rows = log.rows().size();
            int undecidable = (int) observations.stream().filter(o -> o.access() == Access.UNDECIDABLE).count();
            return new LogCoverage(log.source(), log.path(), protocol, rows, requestRows, responseRows,
                unresolvedRows, observations.size(), undecidable);
        }
    }

    /** Zeek 기본 스크립트의 {@code Modbus::function_codes} 이름 → 함수코드. */
    static final class ModbusNames {
        private static final Map<String, Integer> CODES = Map.ofEntries(
            Map.entry("READ_COILS", 0x01),
            Map.entry("READ_DISCRETE_INPUTS", 0x02),
            Map.entry("READ_HOLDING_REGISTERS", 0x03),
            Map.entry("READ_INPUT_REGISTERS", 0x04),
            Map.entry("WRITE_SINGLE_COIL", 0x05),
            Map.entry("WRITE_SINGLE_REGISTER", 0x06),
            Map.entry("READ_EXCEPTION_STATUS", 0x07),
            Map.entry("DIAGNOSTICS", 0x08),
            Map.entry("PROGRAM_484", 0x09),
            Map.entry("POLL_484", 0x0A),
            Map.entry("GET_COMM_EVENT_COUNTER", 0x0B),
            Map.entry("GET_COMM_EVENT_LOG", 0x0C),
            Map.entry("PROGRAM_584_984", 0x0D),
            Map.entry("POLL_584_984", 0x0E),
            Map.entry("WRITE_MULTIPLE_COILS", 0x0F),
            Map.entry("WRITE_MULTIPLE_REGISTERS", 0x10),
            Map.entry("REPORT_SLAVE_ID", 0x11),
            Map.entry("PROGRAM_884_U84", 0x12),
            Map.entry("RESET_COMM_LINK_884_U84", 0x13),
            Map.entry("READ_FILE_RECORD", 0x14),
            Map.entry("WRITE_FILE_RECORD", 0x15),
            Map.entry("MASK_WRITE_REGISTER", 0x16),
            Map.entry("READ_WRITE_MULTIPLE_REGISTERS", 0x17),
            Map.entry("READ_FIFO_QUEUE", 0x18),
            Map.entry("PROGRAM_CONCEPT", 0x28),
            Map.entry("MULTIPLE_FUNCTION_CODES", 0x29),
            Map.entry("ENCAP_INTERFACE_TRANSPORT", 0x2B),
            Map.entry("PROGRAM_UNITY", 0x5A),
            Map.entry("OBJECT_MESSAGING", 0x5B),
            Map.entry("FIRMWARE_REPLACEMENT", 0x7D),
            Map.entry("PROGRAM_584_984_2", 0x7E),
            Map.entry("REPORT_LOCAL_ADDRESS", 0x7F));

        private ModbusNames() {
        }

        /** 모르는 이름이면 -1. Zeek 이 이름을 모를 때 쓰는 {@code unknown-<n>} 은 n 이다. */
        static int code(String name) {
            if (name == null) {
                return -1;
            }
            String base = name.endsWith("_EXCEPTION") ? name.substring(0, name.length() - "_EXCEPTION".length()) : name;
            Integer known = CODES.get(base);
            if (known != null) {
                return known;
            }
            if (base.matches("unknown-\\d{1,3}")) {
                return Integer.parseInt(base.substring("unknown-".length()));
            }
            return -1;
        }
    }
}
