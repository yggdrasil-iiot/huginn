package yggdrasil.huginn.cli;

import yggdrasil.huginn.reconcile.Finding;
import yggdrasil.huginn.zeek.LogCoverage;

import java.util.List;
import java.util.Locale;

/**
 * Zeek 로그 입력의 리포트. 위반 목록은 {@link Report} 와 같은 모양이고, 커버리지가 다르다.
 *
 * <p><b>패킷·바이트·대화 수는 내지 않는다</b> — 로그에는 그 수가 없다. 대신 읽은 행이 요청·응답·
 * 방향 미확정 중 어디로 갔는지를 빠짐없이 나눈다. 방향 미확정 행은 관찰을 지어내지 않고
 * 연결마다 UNDECIDABLE 하나로 남는다.
 */
record ZeekReport(List<LogCoverage> byLog, int undecidableObservations, List<Finding> findings)
    implements Rendered {

    @Override
    public String render() {
        StringBuilder out = new StringBuilder("Huginn — 통신 대사 결과 (Zeek 로그)\n");
        out.append(Report.count("읽은 로그 파일", byLog.size()));
        out.append(Report.count("읽은 행", sum(LogCoverage::rows)));
        out.append(Report.count("요청 행", sum(LogCoverage::requestRows)));
        out.append(Report.count("응답·알림 행", sum(LogCoverage::responseRows)));
        out.append(Report.count("방향 미확정 행", sum(LogCoverage::unresolvedRows)));
        out.append(Report.count("관찰", sum(LogCoverage::observations)));
        out.append(Report.count("UNDECIDABLE 관찰", undecidableObservations));
        out.append("  패킷·바이트 커버리지 없음 — 로그에 없는 통신은 이 수에도 없다\n");
        out.append(logTable());
        return Report.appendFindings(out, findings);
    }

    /** 파일마다 한 행. 순서는 명령줄에 준 순서다. */
    private String logTable() {
        StringBuilder out = new StringBuilder(
            "\n  로그             프로토콜               행       요청  응답·알림     미확정       관찰  UNDEC 관찰\n");
        for (LogCoverage one : byLog) {
            out.append(String.format(Locale.ROOT, "  %-16s %-12s %10s %10s %10s %10s %10s %11s\n",
                one.path(), one.protocol(),
                number(one.rows()), number(one.requestRows()), number(one.responseRows()),
                number(one.unresolvedRows()), number(one.observations()),
                number(one.undecidableObservations())));
        }
        return out.toString();
    }

    private long sum(java.util.function.ToIntFunction<LogCoverage> field) {
        return byLog.stream().mapToLong(field::applyAsInt).sum();
    }

    private static String number(long value) {
        return String.format(Locale.ROOT, "%,d", value);
    }
}
