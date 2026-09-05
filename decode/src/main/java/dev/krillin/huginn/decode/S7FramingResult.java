package dev.krillin.huginn.decode;

import java.util.List;

/**
 * 한 방향 스트림을 S7 으로 프레이밍한 결과.
 *
 * @param undecodedBytes 길이 정합성이 깨진 지점부터 남은 바이트. <b>비-S7 TPKT 는 여기 세지 않는다</b> —
 *                       미해독 바이트가 아니라 우리 관심사가 아닌 프레임이다
 * @param fragmented     COTP 분할(EOT=0)을 만나 자르기를 멈췄는가. 설계 §2 — 재조립하지 않는다
 */
public record S7FramingResult(List<S7Frame> frames, int undecodedBytes, boolean fragmented)
        implements Framing {

    @Override public int frameCount() { return frames.size(); }

    @Override public int leftoverBytes() { return undecodedBytes; }
}
