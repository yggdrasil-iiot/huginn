package dev.krillin.huginn.zeek;

import dev.krillin.huginn.reconcile.Protocol;

/**
 * 로그 한 파일에서 무엇을 봤고 무엇을 관찰로 만들지 않았는지.
 *
 * <p>pcap 입력의 패킷·바이트 커버리지에 해당하는 수는 <b>없다</b>. Zeek 이 본 것만 로그에 있고,
 * Zeek 이 놓친 것은 로그에도 이 수에도 없다. 대신 행이 어디로 갔는지를 빠짐없이 나눈다 —
 * {@code rows == requestRows + responseRows + unresolvedRows}.
 *
 * @param requestRows    요청으로 판정해 관찰을 만든 행. Modbus 의 헤더만 있는 함수는 두 행이 한 요청이다
 * @param responseRows   응답·알림이라 관찰하지 않은 행
 * @param unresolvedRows 방향을 정할 수 없는 행. 관찰을 지어내지 않고 연결마다 UNDECIDABLE 하나로 남긴다
 */
public record LogCoverage(String source,
                          String path,
                          Protocol protocol,
                          int rows,
                          int requestRows,
                          int responseRows,
                          int unresolvedRows,
                          int observations,
                          int undecidableObservations) {
}
