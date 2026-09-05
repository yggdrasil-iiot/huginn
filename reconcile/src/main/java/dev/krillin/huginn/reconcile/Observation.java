package dev.krillin.huginn.reconcile;

import java.time.Instant;

/**
 * 관찰 한 건. 프로토콜 지식은 이 타입을 만드는 쪽(decode)에서 끝난다.
 *
 * 설계 §5-⑤ 에 따라 **요청만** Observation 이 된다. 응답은 출발지·목적지가 뒤집혀 있어
 * 관찰하면 정상 통신이 전부 위반이 된다.
 *
 * @param at        이 관찰이 속한 방향 스트림의 가장 이른 세그먼트 시각. 프레임 단위 시각은 오프셋→시각 맵이 있어야 하므로 1차 범위 밖이고, 한 스트림의 관찰 여럿이 같은 시각을 갖는다
 * @param objectRef 건드린 대상의 프로토콜별 정규화 표기(예: "holding:40001"). 근거 표시용이며 판정에는 쓰지 않는다.
 */
public record Observation(
    Instant at,
    Endpoint source,
    Endpoint target,
    Protocol protocol,
    Access access,
    String objectRef
) {}
