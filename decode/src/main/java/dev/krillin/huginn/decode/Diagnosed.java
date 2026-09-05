package dev.krillin.huginn.decode;

/**
 * 진단까지 함께 낸 결과. <b>테스트 전용</b>이며 {@link ObservationResult} 와 리포트는 손대지 않는다.
 *
 * @param multiClaimConversations 한 대화에서 둘 이상이 주장한 횟수(설계 §3)
 * @param bothDirectionRequestConversations 순회기가 {@code Decoded.bothDirectionsRequested} 가
 *        참인 대화를 센 것. <b>프로토콜 혼합 계수</b>이며 이긴 해독기를 가리지 않는다
 */
record Diagnosed(ObservationResult result,
                 int multiClaimConversations,
                 int bothDirectionRequestConversations) {
}
