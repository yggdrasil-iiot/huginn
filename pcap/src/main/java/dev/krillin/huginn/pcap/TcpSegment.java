package dev.krillin.huginn.pcap;

import java.time.Instant;

/**
 * Ethernet → IPv4 → TCP 로 벗겨낸 세그먼트 한 건.
 *
 * @param syn TCP 헤더 오프셋 13의 0x02.
 * @param ack 같은 바이트의 0x10. syn 과 **따로** 싣는다 — SYN+ACK 는 둘 다 서 있고,
 *            syn 만 보면 서버가 보낸 SYN+ACK 를 연결을 연 쪽으로 오독한다.
 *            여기는 사실만 싣고 "클라이언트"라는 해석은 청크 3이 한다.
 */
public record TcpSegment(
    Instant at, String sourceAddress, int sourcePort,
    String targetAddress, int targetPort, long sequence, byte[] payload,
    boolean truncated, boolean syn, boolean ack) {}
