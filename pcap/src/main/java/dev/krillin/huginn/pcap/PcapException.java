package dev.krillin.huginn.pcap;

/**
 * pcap 입력이 읽을 수 없는 형식이거나 손상되었을 때 던진다.
 * <p>부분 결과를 내는 대신 즉시 던지는 것이 설계 의도다 — 위반이 0건인 리포트는
 * "안전하다"로 오독되므로, 읽지 못한 파일은 조용히 빈 결과가 아니라 예외여야 한다.
 * unchecked 로 둔 이유: checked 였다면 {@code FrameDecoder}·{@code Pipeline}·
 * {@code Huginn.run} 의 시그니처와 Task 14 의 종료 코드 배선이 전부 달라진다.
 */
public class PcapException extends RuntimeException {

    public PcapException(String message) {
        super(message);
    }
}
