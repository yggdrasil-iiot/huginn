package dev.krillin.huginn.decode;

import dev.krillin.huginn.reconcile.Observation;

import java.util.List;

/**
 * 계수 단위는 <b>대화</b>다(리포트가 "대화" 로 적는다). 셋은 배타적이며 합이 전체 대화 수다.
 * <p>해독한 대화에서 나오는 UNDECIDABLE 관찰(잔여 바이트·갭·절단·FC 43)은 여기 세지 않는다 —
 * 그것은 <b>관찰</b> 단위이며 {@code Reconciler.undecidableCount} 가 센다. 두 수는 다르며
 * 리포트가 따로 낸다. 한 칸에 담으면 FC 43 만 잔뜩 든 캡처가 "전부 해독함" 으로 보인다.
 *
 * @param decodedConversations     클라이언트 방향을 정했고 그 방향에서 관찰을 하나 이상 만든 대화 수
 * @param undecidableConversations Modbus 대화이지만 관찰을 하나도 만들지 못한 수
 *                                 (판정 불가, 또는 클라이언트 방향이 캡처에 없음)
 * @param skippedConversations     어느 스트림에서도 유효 프레임이 안 나온 대화 수
 */
public record ObservationResult(List<Observation> observations,
                                int decodedConversations,
                                int undecidableConversations,
                                int skippedConversations) {
}
