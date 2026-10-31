package dev.krillin.huginn.zeek;

import java.util.List;
import java.util.Map;

/**
 * 헤더를 검증하고 행을 필드 이름으로 펼친 Zeek ASCII 로그 한 파일.
 *
 * @param source 사람이 읽는 출처(파일 경로). 오류와 리포트에 그대로 나간다
 * @param path   {@code #path} 헤더 값 — 파일 이름이 아니라 이것으로 무엇인지 정한다
 */
public record ZeekLog(String source, String path, List<Row> rows) {

    /**
     * 한 행. 값이 {@code null} 이면 Zeek 의 unset({@code -})이고, 빈 문자열이면 empty 다 —
     * 둘은 다른 사실이라 섞지 않는다.
     *
     * @param line 파일의 1부터 센 줄 번호
     */
    public record Row(int line, Map<String, String> values) {

        public String get(String field) {
            return values.get(field);
        }

        public boolean isSet(String field) {
            return values.get(field) != null;
        }
    }
}
