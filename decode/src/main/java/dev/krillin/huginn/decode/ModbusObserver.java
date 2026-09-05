package dev.krillin.huginn.decode;

import dev.krillin.huginn.pcap.TcpStream;
import dev.krillin.huginn.reconcile.Access;
import dev.krillin.huginn.reconcile.Endpoint;
import dev.krillin.huginn.reconcile.Observation;
import dev.krillin.huginn.reconcile.Protocol;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 재조립된 스트림에서 <b>요청만</b> {@link Observation} 으로 만든다(설계 §5-⑤). 응답은 출발지·목적지가
 * 뒤집혀 있어 관찰하면 정상 통신이 전부 위반이 된다.
 *
 * <p><b>클라이언트 방향 판정.</b> 신호 둘을 모아 결합한다 — 우선순위가 아니라 일치·불일치다.
 * <ul>
 *   <li><b>S1 · SYN</b> — 두 방향 중 {@code sawSynOnly} 가 참인 방향이 정확히 하나면 그 방향이
 *       클라이언트다. SYN-without-ACK 는 연결을 연 쪽만 보낸다.
 *   <li><b>S2 · PDU 형태</b> — 각 방향에 {@link ModbusShape#ofStream} 을 돌린다. 한쪽만
 *       REQUEST_ONLY 면 그 방향이, REQUEST_ONLY 없이 한쪽만 RESPONSE_ONLY 면 반대 방향이
 *       클라이언트다. <b>양쪽이 같은 형태면 모순</b>이다 — 한 대화에서 양쪽이 같은 역할일 수 없다.
 * </ul>
 * <b>왜 우선순위가 아닌가.</b> 조립기는 4-tuple 만으로 스트림 키를 잡고 연결 경계를 모른다.
 * 같은 4-tuple 위에 역할이 뒤바뀐 연결이 둘 있으면 한 대화로 합쳐지고, {@code sawSynOnly} 는
 * 지금 해석 중인 프레임과 무관한 연결에서 온다. S2 는 해석 대상 프레임 자체에서 나오는 직접
 * 증거다. <b>둘이 어긋나면 어느 쪽도 믿지 않는다.</b>
 *
 * <p><b>포트는 보지 않는다.</b> "낮은 쪽이 서버" 계열 규칙은 거울상을 원리적으로 구별하지 못하고,
 * 포트가 유일한 근거가 되는 영역은 하필 FC 5·6·22 에코 대화 — 전부 WRITE 라 틀리면 대가가
 * 항상 HIGH 다. 이득 영역이 없다. 시각도 보지 않는다(폴링 캡처에서 첫 패킷이 응답일 수 있다).
 */
public final class ModbusObserver {

    private ModbusObserver() {
    }

    public static ObservationResult observe(List<TcpStream> streams) {
        List<Observation> observations = new ArrayList<>();
        int decoded = 0;
        int undecidable = 0;
        int skipped = 0;

        for (List<Decoded> conversation : conversations(streams)) {
            // 대상 외가 절단·갭을 이긴다 — tcpdump -s 96 환경에서는 SSH 스트림도 전부 절단이라
            // 절단이 이기면 커버리지 지표가 비산업 트래픽에 지배된다.
            if (conversation.stream().noneMatch(d -> d.framing().isModbusStream())) {
                skipped++;
                continue;
            }

            Direction client = clientDirection(conversation);
            Decoded clientStream = client == null ? null : find(conversation, client);
            if (clientStream == null) {
                // R1·R2·R4(판정 불가) 또는 R5(고른 방향이 캡처에 없음). 여기서 대화를 끝낸다 —
                // 이어 돌면 같은 대화에서 관찰 두 건과 이중 계수가 난다.
                observations.add(undecidableOf(conversation.get(0).stream()));
                undecidable++;
                continue;
            }

            List<Observation> fromFrames = new ArrayList<>();
            for (ModbusFrame frame : clientStream.framing().frames()) {
                fromFrames.add(observationOf(clientStream.stream(), frame));
            }

            if (fromFrames.isEmpty()) {
                // 클라이언트 방향에서 프레임을 못 뽑았다(그 방향이 프레임 중간에서 시작한 경우).
                // 이 갈래가 없으면 대화가 세 계수 어디에도 안 세인다.
                observations.add(undecidableOf(clientStream.stream()));
                undecidable++;
                continue;
            }

            observations.addAll(fromFrames);
            decoded++;

            // 관찰은 나왔지만 다 봤다고 말하면 안 되는 경우. 대화 계수는 더 건드리지 않는다 —
            // 이 대화는 이미 해독이고, 이것은 관찰 단위의 사실이다.
            if (clientStream.framing().undecodedBytes() > 0
                || clientStream.stream().hasGap()
                || clientStream.stream().truncated()) {
                observations.add(undecidableOf(clientStream.stream()));
            }
        }

        return new ObservationResult(List.copyOf(observations), decoded, undecidable, skipped);
    }

    /**
     * 4-tuple 을 뒤집어 스트림을 대화로 묶는다. 키는 두 (주소, 포트) 쌍을 정렬한 것이라 방향에
     * 무관하고, 포트가 다르면 다른 키이므로 같은 호스트 쌍의 연결 둘은 합쳐지지 않는다.
     * 순회 순서는 각 대화가 입력 목록에 처음 등장한 순서다 — 결정성은 완료 조건이다.
     */
    private static List<List<Decoded>> conversations(List<TcpStream> streams) {
        Map<String, List<Decoded>> byPair = new LinkedHashMap<>();
        for (TcpStream stream : streams) {
            Decoded decoded = new Decoded(stream, ModbusFramer.frames(stream.contiguousPrefix()));
            byPair.computeIfAbsent(conversationKey(stream), k -> new ArrayList<>()).add(decoded);
        }
        return List.copyOf(byPair.values());
    }

    private static String conversationKey(TcpStream stream) {
        String one = stream.sourceAddress() + ":" + stream.sourcePort();
        String other = stream.targetAddress() + ":" + stream.targetPort();
        return one.compareTo(other) <= 0 ? one + "|" + other : other + "|" + one;
    }

    /** 신호 둘을 모아 결합한다. 판정 불가면 null 이다. */
    private static Direction clientDirection(List<Decoded> conversation) {
        Direction bySyn = null;
        for (Decoded decoded : conversation) {
            if (decoded.stream().sawSynOnly()) {
                if (bySyn != null) {
                    bySyn = null;   // 양쪽 다 SYN — 신호 미성립
                    break;
                }
                bySyn = Direction.of(decoded.stream());
            }
        }

        Direction byShape = null;
        Direction requestSide = null;
        Direction responseSide = null;
        int requestCount = 0;
        int responseCount = 0;
        for (Decoded decoded : conversation) {
            switch (ModbusShape.ofStream(decoded.framing().frames())) {
                case REQUEST_ONLY -> {
                    requestCount++;
                    requestSide = Direction.of(decoded.stream());
                }
                case RESPONSE_ONLY -> {
                    responseCount++;
                    responseSide = Direction.of(decoded.stream());
                }
                case UNKNOWN -> { }
            }
        }
        if (requestCount > 1 || responseCount > 1) {
            return null;   // R1 — 양쪽이 같은 형태다. 대화가 잘못 묶였거나 재조립이 어긋났다
        }
        if (requestCount == 1) {
            byShape = requestSide;
        } else if (responseCount == 1) {
            byShape = responseSide.reversed();
        }

        if (bySyn != null && byShape != null && !bySyn.equals(byShape)) {
            return null;   // R2 — 두 신호가 어긋난다. 어느 쪽도 믿지 않는다
        }
        return byShape != null ? byShape : bySyn;   // R3 · R4(둘 다 null)
    }

    /** R5 의 사후 가드를 겸한다 — 고른 방향이 캡처에 없으면 null 이다. */
    private static Decoded find(List<Decoded> conversation, Direction direction) {
        for (Decoded decoded : conversation) {
            if (Direction.of(decoded.stream()).equals(direction)) {
                return decoded;
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
            ModbusAccess.of(frame.functionCode()),
            ModbusObjectRef.of(frame.functionCode(), frame.pdu()));
    }

    /** 무엇을 건드렸는지 모르므로 objectRef 는 "-" 다. 지어내면 근거가 아니라 추측이 된다. */
    private static Observation undecidableOf(TcpStream stream) {
        return new Observation(
            stream.at(),
            new Endpoint(stream.sourceAddress(), stream.sourcePort()),
            new Endpoint(stream.targetAddress(), stream.targetPort()),
            Protocol.MODBUS_TCP,
            Access.UNDECIDABLE,
            "-");
    }

    private record Decoded(TcpStream stream, FramingResult framing) {
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
