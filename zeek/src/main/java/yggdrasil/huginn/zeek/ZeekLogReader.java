package yggdrasil.huginn.zeek;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Zeek ASCII(TSV) 로그를 읽는다. JSON 줄 형식은 받지 않는다.
 *
 * <p>헤더가 선언한 구분자·unset·empty 표기를 <b>그대로 따른다</b> — 기본값을 가정하지 않는다.
 * 한 파일에 헤더 묶음이 여러 번 나와도(로그를 이어 붙인 경우) 묶음마다 다시 검증한다.
 * 형식이 어긋나면 줄 번호를 들고 실패한다. 절반만 읽은 로그로 대사하면 "위반 없음" 이
 * 거짓이 될 수 있다.
 */
public final class ZeekLogReader {

    private ZeekLogReader() {
    }

    public static ZeekLog parse(String text, String source) {
        String body = text.startsWith("﻿") ? text.substring(1) : text;
        if (body.stripLeading().startsWith("{")) {
            throw new ZeekLogException(source + ": JSON 줄 형식은 읽지 않는다 — Zeek 을 "
                + "LogAscii::use_json=F(기본값)로 돌려 TSV 로 내야 한다");
        }

        Header header = new Header();
        String path = null;
        List<ZeekLog.Row> rows = new ArrayList<>();
        String[] lines = body.split("\n", -1);

        for (int i = 0; i < lines.length; i++) {
            int lineNumber = i + 1;
            String line = lines[i].endsWith("\r") ? lines[i].substring(0, lines[i].length() - 1) : lines[i];
            if (line.isEmpty()) {
                continue;
            }
            if (line.startsWith("#")) {
                if (header.accept(line, source, lineNumber)) {
                    header.validate(source, lineNumber);
                    if (path != null && !path.equals(header.path)) {
                        throw new ZeekLogException(source + ":" + lineNumber + ": 한 파일에 #path 가 둘이다 ("
                            + path + ", " + header.path + ")");
                    }
                    path = header.path;
                }
                continue;
            }
            if (!header.complete()) {
                throw new ZeekLogException(source + ":" + lineNumber
                    + ": 헤더(#separator·#path·#fields·#types)보다 데이터가 먼저 나왔다");
            }
            rows.add(header.row(line, source, lineNumber));
        }

        if (path == null) {
            throw new ZeekLogException(source + ": Zeek 로그 헤더가 없다");
        }
        return new ZeekLog(source, path, List.copyOf(rows));
    }

    /** 현재 헤더 묶음. {@code #fields}/{@code #types} 가 다시 나오면 새 묶음이다. */
    private static final class Header {
        private String separator;
        private String unset;
        private String empty;
        private String path;
        private List<String> fields;
        private List<String> types;
        private boolean validated;

        /** @return 이 줄로 묶음이 완성되어 검증할 차례면 true */
        boolean accept(String line, String source, int lineNumber) {
            if (line.startsWith("#separator ")) {
                separator = unescape(line.substring("#separator ".length()));
                if (separator.isEmpty()) {
                    throw new ZeekLogException(source + ":" + lineNumber + ": #separator 가 비었다");
                }
                fields = null;
                types = null;
                validated = false;
                return false;
            }
            if (separator == null) {
                throw new ZeekLogException(source + ":" + lineNumber + ": #separator 가 첫 헤더가 아니다");
            }
            String[] parts = line.split(java.util.regex.Pattern.quote(separator), -1);
            String key = parts[0];
            switch (key) {
                case "#unset_field" -> unset = single(parts, source, lineNumber);
                case "#empty_field" -> empty = single(parts, source, lineNumber);
                case "#path" -> path = single(parts, source, lineNumber);
                case "#fields" -> {
                    fields = List.of(parts).subList(1, parts.length);
                    validated = false;
                }
                case "#types" -> {
                    types = List.of(parts).subList(1, parts.length);
                    validated = false;
                }
                default -> {
                    // #set_separator · #open · #close 는 대사에 쓰지 않는다.
                }
            }
            return !validated && complete();
        }

        boolean complete() {
            return separator != null && unset != null && empty != null && path != null
                && fields != null && types != null;
        }

        void validate(String source, int lineNumber) {
            String where = source + ":" + lineNumber + ": ";
            if (fields.size() != types.size()) {
                throw new ZeekLogException(where + "#fields(" + fields.size() + ") 와 #types("
                    + types.size() + ") 의 수가 다르다");
            }
            Set<String> seen = new HashSet<>();
            for (String field : fields) {
                if (!seen.add(field)) {
                    throw new ZeekLogException(where + "열 이름이 겹친다: " + field);
                }
            }
            if (!ZeekSchema.supports(path)) {
                throw new ZeekLogException(where + "읽지 않는 로그다: #path " + path
                    + " (읽는 것: " + ZeekSchema.supported() + ")");
            }
            for (Map.Entry<String, String> want : ZeekSchema.required(path).entrySet()) {
                int at = fields.indexOf(want.getKey());
                if (at < 0) {
                    throw new ZeekLogException(where + path + " 에 필요한 열이 없다: " + want.getKey());
                }
                if (!types.get(at).equals(want.getValue())) {
                    throw new ZeekLogException(where + path + " 의 " + want.getKey() + " 타입이 "
                        + types.get(at) + " 이다 (기대: " + want.getValue() + ")");
                }
            }
            validated = true;
        }

        ZeekLog.Row row(String line, String source, int lineNumber) {
            String[] parts = line.split(java.util.regex.Pattern.quote(separator), -1);
            if (parts.length != fields.size()) {
                throw new ZeekLogException(source + ":" + lineNumber + ": 열이 " + parts.length
                    + " 개다 (#fields 는 " + fields.size() + " 개)");
            }
            Map<String, String> values = new HashMap<>();
            for (int i = 0; i < parts.length; i++) {
                String raw = parts[i];
                values.put(fields.get(i),
                    raw.equals(unset) ? null : raw.equals(empty) ? "" : unescape(raw));
            }
            return new ZeekLog.Row(lineNumber, values);
        }

        private static String single(String[] parts, String source, int lineNumber) {
            if (parts.length != 2) {
                throw new ZeekLogException(source + ":" + lineNumber + ": " + parts[0] + " 값이 하나가 아니다");
            }
            return parts[1];
        }
    }

    /** Zeek 은 구분자와 출력할 수 없는 바이트를 {@code \xHH} 로, 역슬래시를 {@code \\} 로 낸다. */
    static String unescape(String raw) {
        if (raw.indexOf('\\') < 0) {
            return raw;
        }
        StringBuilder out = new StringBuilder(raw.length());
        for (int i = 0; i < raw.length(); i++) {
            char c = raw.charAt(i);
            if (c == '\\' && i + 3 < raw.length() &&raw.charAt(i + 1) == 'x'
                && isHex(raw.charAt(i + 2)) && isHex(raw.charAt(i + 3))) {
                out.append((char) Integer.parseInt(raw.substring(i + 2, i + 4), 16));
                i += 3;
            } else if (c == '\\' && i + 1 < raw.length() && raw.charAt(i + 1) == '\\') {
                out.append('\\');
                i += 1;
            } else {
                out.append(c);
            }
        }
        return out.toString();
    }

    private static boolean isHex(char c) {
        return Character.digit(c, 16) >= 0;
    }
}
