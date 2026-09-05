package dev.krillin.huginn.pcap;

import java.time.Instant;

/**
 * libpcap 파일에서 읽어낸 패킷 한 건 — 캡처 시각, 저장된 바이트, 원본 길이.
 *
 * @param at 패킷 헤더의 {@code ts_sec}·{@code ts_usec} 를 합성한 캡처 시각
 * @param data 실제로 저장된 바이트({@code incl_len} 만큼) — 캡처가 잘렸다면 원본보다 짧다
 * @param originalLength 와이어 상의 원본 길이({@code orig_len}). {@code int} 가 아니라
 *     {@code long} 인 이유 — {@code orig_len} 은 unsigned 32비트다. {@code int} 로 좁히면
 *     {@code 0xFFFFFFFF} 인 파일에서 {@code -1} 이 되어 {@link #truncated()} 가 false 를
 *     내고, 잘린 캡처가 온전한 것으로 하류에 흘러간다.
 */
public record CapturedPacket(Instant at, byte[] data, long originalLength) {

    /** incl_len &lt; orig_len — 캡처가 잘렸다. 하류는 이 패킷을 온전한 것으로 취급하면 안 된다. */
    public boolean truncated() {
        return data.length < originalLength;
    }
}
