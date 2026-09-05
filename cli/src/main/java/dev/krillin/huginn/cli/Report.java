package dev.krillin.huginn.cli;

import dev.krillin.huginn.reconcile.Finding;
import dev.krillin.huginn.reconcile.Observation;

import java.util.List;
import java.util.Locale;

/**
 * 대사 결과와 커버리지를 함께 든다. {@code ReconcileResult} 에는 패킷 수를 담을 자리가 없으므로
 * 여기서 둘을 합친다.
 *
 * <p><b>UNDECIDABLE 은 서로 다른 두 수다.</b> {@code undecidableConversations} 는 관찰을 하나도
 * 만들지 못한 <b>대화</b> 수이고, {@code undecidableObservations} 는 모든 UNDECIDABLE <b>관찰</b>
 * 수다(판정 불가 대화가 낸 1건 + 해독한 대화의 잔여·갭·절단·FC 43). 관찰 쪽을 빼면 FC 43 만
 * 잔뜩 든 캡처가 "대화 전부 해독" 으로 보이고, 대화 쪽을 빼면 한 방향만 잡힌 캡처가 드러나지
 * 않는다. 둘 다 낸다.
 *
 * <p>줄바꿈은 {@code %n} 이 아니라 {@code \n} 으로 낸다 — 로케일과 마찬가지로 리포트가
 * 환경을 타면 "같은 입력에 같은 리포트" 를 플랫폼별로 다시 증명해야 한다.
 */
record Report(int packetsProcessed,
              int packetsSkipped,
              int decodedConversations,
              int skippedConversations,
              int undecidableConversations,
              int undecidableObservations,
              List<Finding> findings) {

    String render() {
        StringBuilder out = new StringBuilder("Huginn — 통신 대사 결과\n");
        out.append(count("처리 패킷", packetsProcessed));
        out.append(count("대상 외 패킷", packetsSkipped));
        out.append(count("해독한 대화", decodedConversations));
        out.append(count("대상 외 대화", skippedConversations));
        out.append(count("UNDECIDABLE 대화", undecidableConversations));
        out.append(count("UNDECIDABLE 관찰", undecidableObservations));

        if (findings.isEmpty()) {
            return out.append("\n위반 없음\n").toString();
        }

        out.append("\n위반 ").append(findings.size()).append("건\n");
        for (Finding finding : findings) {
            Observation evidence = finding.evidence();
            out.append(String.format(Locale.ROOT, "  [%s] %s → %s  %s %s  %s",
                    finding.severity(), evidence.source(), evidence.target(),
                    evidence.protocol(), evidence.access(), evidence.objectRef()))
                .append('\n')
                .append("           ").append(finding.detail()).append('\n');
        }
        return out.toString();
    }

    /**
     * 천 단위 구분자는 Locale.ROOT 로 낸다 — 기본 로케일에 맡기면 리포트가 환경을 탄다.
     * <p>여백은 글자 수가 아니라 <b>표시 폭</b>으로 맞춘다. {@code %-18s} 는 한글 한 자를 1 로
     * 세지만 콘솔에서는 2 칸을 차지해, 라벨마다 한글 비율이 다른 이 표가 어긋난다.
     */
    private static String count(String label, int value) {
        int padding = Math.max(1, LABEL_WIDTH - displayWidth(label));
        return "  " + label + " ".repeat(padding)
            + String.format(Locale.ROOT, "%8s", String.format(Locale.ROOT, "%,d", value)) + "\n";
    }

    private static final int LABEL_WIDTH = 20;

    /** 한중일 문자와 한글은 콘솔에서 두 칸을 차지한다. 나머지는 한 칸으로 본다. */
    private static int displayWidth(String text) {
        int width = 0;
        for (int i = 0; i < text.length(); i++) {
            width += isWide(text.charAt(i)) ? 2 : 1;
        }
        return width;
    }

    private static boolean isWide(char c) {
        Character.UnicodeBlock block = Character.UnicodeBlock.of(c);
        return block == Character.UnicodeBlock.HANGUL_SYLLABLES
            || block == Character.UnicodeBlock.HANGUL_JAMO
            || block == Character.UnicodeBlock.HANGUL_COMPATIBILITY_JAMO
            || block == Character.UnicodeBlock.CJK_UNIFIED_IDEOGRAPHS
            || block == Character.UnicodeBlock.CJK_SYMBOLS_AND_PUNCTUATION;
    }
}
