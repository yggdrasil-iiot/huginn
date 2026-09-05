package dev.krillin.huginn.decode;

import dev.krillin.huginn.pcap.TcpStream;

/**
 * 스트림 하나에 대한 한 프로토콜의 증거.
 *
 * <p>프레임 자체를 노출하지 않는 것이 요점이다. 순회기는 개수·바이트 수와
 * {@link TcpStream} 의 {@code hasGap}·{@code truncated} 만 보고, 프레임·함수코드·PDU 형태는
 * 해독기 밖으로 나오지 않는다.
 *
 * @param frameCount    <b>수용된 구간들</b>에서 나온 프레임 수. 0 이면 이 스트림은 이 프로토콜이 아니다
 * @param unreadBytes   받았지만 프레임이 덮지 못한 바이트. 첫 구간의 잔여 + 거부된 구간의 몫이며,
 *                      구간 종류별 계산은 {@link RunReader} 가 한다
 * @param capturedBytes 이 스트림에서 실제로 받은 바이트. 구멍은 {@code stream.missingBytes()} 가 센다
 * @param rejectedRuns  거부한 구간 수
 * @param dirtyRuns     그중 프레임이 나왔던 구간 수. <b>진단 전용</b>이며 판정에 쓰지 않는다 —
 *                      {@link RunReader} 를 한 번 더 돌리지 않으려고 여기 실어 나른다
 */
record StreamEvidence(TcpStream stream, int frameCount, long unreadBytes, long capturedBytes,
                      int rejectedRuns, int dirtyRuns) {
}
