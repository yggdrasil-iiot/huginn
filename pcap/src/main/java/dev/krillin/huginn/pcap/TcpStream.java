package dev.krillin.huginn.pcap;

import java.time.Instant;
import java.util.List;

/**
 * 한 방향의 재조립된 바이트 흐름.
 *
 * @param at         이 방향에서 관찰된 세그먼트 중 <b>가장 이른 at</b>. 입력 순서가 아니라 시각이
 *                   기준이다 — Observation.at 이 이 값에서 오므로 "입력 순서상 첫 번째" 로 읽으면
 *                   순서가 뒤바뀐 캡처에서 리포트의 시각이 뒤집힌다.
 * @param runs       연속한 바이트 구간들. 구멍을 만나면 끊고 새 구간을 시작한다 —
 *                   <b>이어붙이지 않는다.</b> 원소는 절대 빈 배열이 아니며, 데이터가 없는 스트림은
 *                   <b>빈 목록</b>이다.
 *                   <b>주의:</b> {@code byte[]} 를 담으므로 이 record 의 {@code equals} 는
 *                   여전히 배열 참조 비교다.
 * @param missingBytes 구간 사이 구멍들의 크기 합. <b>캡처가 받지 못한 바이트</b>이며
 *                   "받았지만 해독 못 한" 것과는 다른 값이다.
 * @param truncated  이 방향의 세그먼트 중 하나라도 절단됐으면 true. 스트림 전체를 온전한 것으로 취급하면 안 된다.
 * @param sawSynOnly 이 방향에서 <b>SYN 은 서 있고 ACK 는 서 있지 않은</b> 세그먼트를 봤다.
 *                   그런 세그먼트는 연결을 연 쪽만 보낸다. SYN+ACK 는 여기 해당하지 않는다.
 */
public record TcpStream(
    Instant at, String sourceAddress, int sourcePort, String targetAddress, int targetPort,
    List<byte[]> runs, long missingBytes, boolean truncated, boolean sawSynOnly) {

    /** 구간이 둘 이상이면 그 사이에 구멍이 있었다는 뜻이다. */
    public boolean hasGap() {
        return runs.size() > 1;
    }
}
