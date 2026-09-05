package dev.krillin.huginn.pcap;

import java.time.Instant;

/**
 * 한 방향의 재조립된 바이트 흐름.
 *
 * @param at         이 방향에서 관찰된 세그먼트 중 **가장 이른 at**. 입력 순서가 아니라 시각이 기준이다 —
 *                   Observation.at 이 이 값에서 오므로 "입력 순서상 첫 번째" 로 읽으면
 *                   순서가 뒤바뀐 캡처에서 리포트의 시각이 뒤집힌다.
 * @param truncated  이 방향의 세그먼트 중 하나라도 절단됐으면 true. 스트림 전체를 온전한 것으로 취급하면 안 된다.
 * @param sawSynOnly 이 방향에서 **SYN 은 서 있고 ACK 는 서 있지 않은** 세그먼트를 봤다.
 *                   그런 세그먼트는 연결을 연 쪽만 보낸다. SYN+ACK 는 여기 해당하지 않는다.
 */
public record TcpStream(
    Instant at, String sourceAddress, int sourcePort, String targetAddress, int targetPort,
    byte[] contiguousPrefix, boolean hasGap, boolean truncated, boolean sawSynOnly) {}
