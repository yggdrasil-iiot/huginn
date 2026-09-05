package dev.krillin.huginn.decode;

import dev.krillin.huginn.pcap.TcpStream;
import dev.krillin.huginn.reconcile.Observation;

import java.util.List;

/**
 * 해독기가 대화 하나를 읽은 결과.
 *
 * @param requestObservations 요청 프레임에서 만든 관찰. 응답은 들어가지 않는다(1차 설계 §5-⑤)
 * @param client              요청을 보낸 방향의 증거. <b>null 이면 판정 불가</b>다.
 *                            {@link TcpStream} 이 아니라 증거를 돌려주는 이유 — TcpStream 은
 *                            {@code byte[]} 컴포넌트를 가진 record 라 equals 가 배열 참조 비교다.
 *                            되짚으려 하면 동일 인스턴스일 때만 우연히 동작한다
 * @param tailUndecidable     프레임은 뽑았으나 해석하지 않은 것이 대화 어딘가에 있는가.
 *                            S7 이 Userdata(ROSCTR 7)나 COTP 분할을 만났을 때 세운다 — 그것들은
 *                            응답 방향에도 실리므로 client 의 잔여만 보는 규칙으로는 잡히지 않는다.
 *                            Modbus 는 항상 false 다: 그쪽 잔여·갭·절단은 client 증거로 이미 흐른다
 * @param bothDirectionsRequested client == null 인 이유가 <b>요청 방향이 둘</b>이어서인가.
 *                            요청 방향 0 개(응답만 잡힘·Userdata 만)와 2 개(한 4-tuple 에 연결이 둘)를
 *                            순회기는 구별할 수 없다 — 둘 다 frameCount > 0 이기 때문이다.
 *                            해독기만 아는 사실이므로 해독기가 싣는다
 */
record Decoded(List<Observation> requestObservations,
               StreamEvidence client,
               boolean tailUndecidable,
               boolean bothDirectionsRequested) {

    static Decoded undecided(boolean bothDirectionsRequested) {
        return new Decoded(List.of(), null, false, bothDirectionsRequested);
    }
}
