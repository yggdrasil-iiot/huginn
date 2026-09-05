package dev.krillin.huginn.decode;

import dev.krillin.huginn.pcap.TcpStream;

import java.util.List;

/**
 * Modbus 전용 진입점. <b>Modbus 해독기 하나만</b> 등록해 순회기를 돌린다.
 *
 * <p>남겨둔 이유는 {@code ModbusObserverTest} 20건이 이것을 부르고, 그 테스트가 증명하려는 것이
 * Modbus 판정이지 다중 프로토콜 공존이 아니기 때문이다. 공존은 별도 테스트가 증명한다.
 *
 * <p>판정 로직은 {@link ModbusDecoder}, 대화 순회와 계수는 {@link TrafficObserver} 에 있다.
 */
public final class ModbusObserver {

    private ModbusObserver() {
    }

    public static ObservationResult observe(List<TcpStream> streams) {
        return TrafficObserver.observe(streams, List.of(new ModbusDecoder()));
    }
}
