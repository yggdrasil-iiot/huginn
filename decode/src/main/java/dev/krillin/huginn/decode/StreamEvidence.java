package dev.krillin.huginn.decode;

import dev.krillin.huginn.pcap.TcpStream;

/**
 * 스트림 하나에 대한 한 프로토콜의 증거.
 *
 * <p>프레임 자체를 노출하지 않는 것이 요점이다. 순회기는 개수와 잔여 여부, 그리고
 * {@link TcpStream} 의 {@code hasGap}·{@code truncated} 만 보고, 프레임·함수코드·PDU 형태는
 * 해독기 밖으로 나오지 않는다.
 *
 * @param frameCount    이 프로토콜의 유효 프레임 수. 0 이면 이 스트림은 이 프로토콜이 아니다
 * @param leftoverBytes 프레임 뒤에 해독하지 못한 바이트가 남았는가
 */
record StreamEvidence(TcpStream stream, int frameCount, boolean leftoverBytes) {
}
