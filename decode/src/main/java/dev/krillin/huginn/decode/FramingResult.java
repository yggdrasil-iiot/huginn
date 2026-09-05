package dev.krillin.huginn.decode;

import java.util.List;

/**
 * 한 방향 스트림을 프레이밍한 결과.
 *
 * @param isModbusStream 유효 프레임을 한 개 이상 뽑았는가. false 면 이 스트림은 산업 트래픽이 아니라
 *                       대상 외이며, undecodedBytes 를 커버리지에 계수하지 않는다.
 */
public record FramingResult(List<ModbusFrame> frames, int undecodedBytes, boolean isModbusStream) {
}
