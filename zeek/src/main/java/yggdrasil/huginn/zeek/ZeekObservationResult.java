package yggdrasil.huginn.zeek;

import yggdrasil.huginn.reconcile.Observation;

import java.util.List;

/** 로그에서 만든 관찰과 파일별 커버리지. 관찰 순서는 넘겨받은 파일 순서, 파일 안에서는 행 순서다. */
public record ZeekObservationResult(List<Observation> observations, List<LogCoverage> byLog) {
}
