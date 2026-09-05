package dev.krillin.huginn.decode;

import dev.krillin.huginn.reconcile.Protocol;

/**
 * 프로토콜 하나의 커버리지.
 *
 * <p>2차 설계 §6 이 "99% S7 인 캡처에서 Modbus 가 얼마나 얇은지 리포트만 보고는 알 수 없다" 고
 * 적고 미룬 것을 채운다. 그때는 합산을 유지해야 이음매 판정이 흐려지지 않았다.
 *
 * <p><b>대화를 주장한 프로토콜이 0 이어도 행을 낸다.</b> 151020 의 {@code MODBUS_TCP 0} 이야말로
 * 1차가 기록한 "이 캡처에는 Modbus 가 한 프레임도 없다" 를 리포트가 직접 말하는 것이다.
 *
 * @param decodedConversations     이 프로토콜이 이겨서 관찰을 만든 대화 수
 * @param undecidableConversations 이겼으나 관찰을 하나도 못 만든 대화 수
 * @param observations             이 프로토콜로 만든 관찰 총수
 * @param undecidableObservations  그중 access 가 UNDECIDABLE 인 것
 * @param unobservedBytes          이 프로토콜이 이긴 대화에서 못 본 바이트
 * @param industrialBytes          그 대화들이 실제로 오갔던 바이트
 */
public record ProtocolCoverage(Protocol protocol,
                               int decodedConversations,
                               int undecidableConversations,
                               int observations,
                               int undecidableObservations,
                               long unobservedBytes,
                               long industrialBytes) {
}
