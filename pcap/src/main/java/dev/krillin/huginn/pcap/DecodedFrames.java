package dev.krillin.huginn.pcap;

import java.util.List;

/**
 * {@link FrameDecoder#decode} 의 결과.
 *
 * @param skipped 산업 트래픽 대상이 아니어서 건너뛴 패킷 수 — ARP 등 비IPv4·UDP·IP 단편·
 *                **헤더보다 짧은 프레임**. 페이로드만 잘린 프레임은 여기 세지 않는다.
 *                그것은 truncated 로 표시해 그대로 흘린다(같은 Step 의 구현 규칙).
 */
public record DecodedFrames(List<TcpSegment> segments, int skipped) {}
