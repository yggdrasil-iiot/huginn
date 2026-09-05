package dev.krillin.huginn.decode;

import dev.krillin.huginn.pcap.TcpStream;
import dev.krillin.huginn.reconcile.Endpoint;
import dev.krillin.huginn.reconcile.Observation;
import dev.krillin.huginn.reconcile.Protocol;

import java.util.ArrayList;
import java.util.List;

/**
 * Modbus/TCP 판정. 1차의 {@code ModbusObserver} 안에 있던 프로토콜 고유 로직이 그대로 왔다 —
 * S1(SYN)·S2(PDU 형태) 신호와 결합 규칙 R1~R5, 함수코드 매핑.
 *
 * <p><b>클라이언트 방향 판정.</b> 신호 둘을 모아 결합한다 — 우선순위가 아니라 일치·불일치다.
 * <ul>
 *   <li><b>S1 · SYN</b> — 두 방향 중 {@code sawSynOnly} 가 참인 방향이 정확히 하나면 그 방향이
 *       클라이언트다. SYN-without-ACK 는 연결을 연 쪽만 보낸다.
 *   <li><b>S2 · PDU 형태</b> — 각 방향에 {@link ModbusShape#ofStream} 을 돌린다. 한쪽만
 *       REQUEST_ONLY 면 그 방향이, REQUEST_ONLY 없이 한쪽만 RESPONSE_ONLY 면 반대 방향이
 *       클라이언트다. <b>양쪽이 같은 형태면 모순</b>이다.
 * </ul>
 * <b>왜 우선순위가 아닌가.</b> 조립기는 4-tuple 만으로 스트림 키를 잡고 연결 경계를 모른다.
 * 같은 4-tuple 위에 역할이 뒤바뀐 연결이 둘 있으면 한 대화로 합쳐지고, {@code sawSynOnly} 는
 * 지금 해석 중인 프레임과 무관한 연결에서 온다. <b>둘이 어긋나면 어느 쪽도 믿지 않는다.</b>
 *
 * <p><b>포트는 보지 않는다.</b> "낮은 쪽이 서버" 계열 규칙은 거울상을 원리적으로 구별하지 못하고,
 * 포트가 유일한 근거가 되는 영역은 하필 FC 5·6·22 에코 대화 — 전부 WRITE 라 틀리면 대가가
 * 항상 HIGH 다. 시각도 보지 않는다(폴링 캡처에서 첫 패킷이 응답일 수 있다).
 *
 * <p>{@link StreamEvidence} 가 프레임을 노출하지 않으므로 판정할 때 프레이밍을 다시 돌린다.
 * 프로토콜 지식이 순회기로 새지 않게 하려고 치르는 비용이다.
 */
final class ModbusDecoder implements ProtocolDecoder {

    @Override
    public Protocol protocol() {
        return Protocol.MODBUS_TCP;
    }

    @Override
    public StreamEvidence scan(TcpStream stream) {
        RunReader.Reading<FramingResult> reading = read(stream);
        return new StreamEvidence(stream, framesOf(reading).size(), reading.unreadBytes(),
            reading.capturedBytes(), reading.rejectedRuns(), reading.dirtyRuns());
    }

    private static RunReader.Reading<FramingResult> read(TcpStream stream) {
        return RunReader.read(stream, ModbusFramer::frames);
    }

    /**
     * 수용된 구간들의 프레임을 순서대로 이어 붙인다 — 구간별로 따로 판정하지 않는다.
     *
     * <p>두 구간의 형태가 어긋나면 {@link ModbusShape#ofStream} 이 합쳐서 UNKNOWN 을 내고,
     * 그것은 판정 불가 쪽으로 기우는 보수적 방향이라 이 설계의 원칙과 맞다.
     */
    private static List<ModbusFrame> framesOf(RunReader.Reading<FramingResult> reading) {
        List<ModbusFrame> frames = new ArrayList<>();
        for (FramingResult one : reading.accepted()) {
            frames.addAll(one.frames());
        }
        return frames;
    }

    @Override
    public Decoded decode(List<StreamEvidence> conversation) {
        Direction bySyn = synSignal(conversation);
        ShapeSignal byShape = shapeSignal(conversation);

        if (byShape.contradiction()) {
            return Decoded.undecided(byShape.bothRequest());   // R1
        }
        if (bySyn != null && byShape.direction() != null && !bySyn.equals(byShape.direction())) {
            return Decoded.undecided(false);                   // R2 — 두 신호가 어긋난다
        }
        Direction chosen = byShape.direction() != null ? byShape.direction() : bySyn;
        if (chosen == null) {
            return Decoded.undecided(false);                   // R4 — 둘 다 미성립
        }
        StreamEvidence client = find(conversation, chosen);
        if (client == null) {
            return Decoded.undecided(false);                   // R5 — 고른 방향이 캡처에 없다
        }

        List<Observation> observations = new ArrayList<>();
        for (ModbusFrame frame : framesOf(read(client.stream()))) {
            observations.add(observationOf(client.stream(), frame));
        }
        return new Decoded(observations, client, false, false);
    }

    /** S1 — {@code sawSynOnly} 인 방향이 정확히 하나일 때만 성립한다. */
    private static Direction synSignal(List<StreamEvidence> conversation) {
        Direction bySyn = null;
        for (StreamEvidence evidence : conversation) {
            if (evidence.stream().sawSynOnly()) {
                if (bySyn != null) {
                    return null;   // 양쪽 다 SYN — 신호 미성립
                }
                bySyn = Direction.of(evidence.stream());
            }
        }
        return bySyn;
    }

    /**
     * S2 — PDU 형태.
     *
     * @param contradiction R1 — 양쪽이 같은 형태다
     * @param bothRequest   그 모순이 <b>양쪽 다 REQUEST_ONLY</b> 인 경우인가.
     *                      양쪽이 RESPONSE_ONLY 인 R1 은 요청 방향이 <b>0 개</b>라 false 다 —
     *                      설계 §3 의 bothDirectionsRequested 계약이 그 둘을 구별한다
     */
    private record ShapeSignal(Direction direction, boolean contradiction, boolean bothRequest) {
    }

    private static ShapeSignal shapeSignal(List<StreamEvidence> conversation) {
        Direction requestSide = null;
        Direction responseSide = null;
        int requestCount = 0;
        int responseCount = 0;

        for (StreamEvidence evidence : conversation) {
            switch (ModbusShape.ofStream(framesOf(read(evidence.stream())))) {
                case REQUEST_ONLY -> {
                    requestCount++;
                    requestSide = Direction.of(evidence.stream());
                }
                case RESPONSE_ONLY -> {
                    responseCount++;
                    responseSide = Direction.of(evidence.stream());
                }
                case UNKNOWN -> { }
            }
        }

        if (requestCount > 1 || responseCount > 1) {
            return new ShapeSignal(null, true, requestCount > 1);
        }
        if (requestCount == 1) {
            return new ShapeSignal(requestSide, false, false);
        }
        if (responseCount == 1) {
            return new ShapeSignal(responseSide.reversed(), false, false);
        }
        return new ShapeSignal(null, false, false);
    }

    /** R5 의 사후 가드를 겸한다 — 고른 방향이 캡처에 없으면 null 이다. */
    private static StreamEvidence find(List<StreamEvidence> conversation, Direction direction) {
        for (StreamEvidence evidence : conversation) {
            if (Direction.of(evidence.stream()).equals(direction)) {
                return evidence;
            }
        }
        return null;
    }

    private static Observation observationOf(TcpStream stream, ModbusFrame frame) {
        return new Observation(
            stream.at(),
            new Endpoint(stream.sourceAddress(), stream.sourcePort()),
            new Endpoint(stream.targetAddress(), stream.targetPort()),
            Protocol.MODBUS_TCP,
            ModbusAccess.of(frame.functionCode(), frame.pdu()),
            ModbusObjectRef.of(frame.functionCode(), frame.pdu()));
    }

    private record Direction(String sourceAddress, int sourcePort, String targetAddress, int targetPort) {

        static Direction of(TcpStream stream) {
            return new Direction(stream.sourceAddress(), stream.sourcePort(),
                stream.targetAddress(), stream.targetPort());
        }

        Direction reversed() {
            return new Direction(targetAddress, targetPort, sourceAddress, sourcePort);
        }
    }
}
