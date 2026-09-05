package dev.krillin.huginn.decode;

import dev.krillin.huginn.pcap.TcpStream;
import dev.krillin.huginn.reconcile.Access;
import dev.krillin.huginn.reconcile.Endpoint;
import dev.krillin.huginn.reconcile.Observation;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 대화 순회와 계수. <b>프로토콜을 모른다.</b>
 *
 * <p>대화는 4-tuple 을 뒤집어 묶고, 순서는 {@code LinkedHashMap} 으로 최초 등장 순서를 유지한다 —
 * 리포트의 결정성이 여기서 시작된다.
 *
 * <p><b>계수는 세 칸이며 배타적이고 합이 전체 대화 수다.</b> 순회가 한 번뿐이고 모든 분기가
 * 정확히 하나의 계수를 올리므로 그 불변식이 구조적으로 유지된다.
 */
public final class TrafficObserver {

    private static final List<ProtocolDecoder> DECODERS =
        List.of(new ModbusDecoder(), new S7Decoder());

    private TrafficObserver() {
    }

    /** cli 가 부르는 유일한 판. */
    public static ObservationResult observe(List<TcpStream> streams) {
        return observe(streams, DECODERS);
    }

    static ObservationResult observe(List<TcpStream> streams, List<ProtocolDecoder> decoders) {
        return observeWithDiagnostics(streams, decoders).result();
    }

    /**
     * 진단까지 함께 낸다 — <b>테스트 전용</b>이며 {@link ObservationResult} 와 리포트는 손대지 않는다.
     */
    static Diagnosed observeWithDiagnostics(List<TcpStream> streams, List<ProtocolDecoder> decoders) {
        List<Observation> observations = new ArrayList<>();
        int decoded = 0;
        int undecidable = 0;
        int skipped = 0;
        int multiClaim = 0;
        int bothDirections = 0;
        long unobserved = 0;
        long industrial = 0;
        int rejectedRuns = 0;
        int dirtyRuns = 0;

        // 프로토콜별 누적. 등록 순서를 그대로 쓰므로 리포트의 표 순서가 고정된다.
        // 칸: 0 해독 대화 · 1 판정불가 대화 · 2 관찰 · 3 UNDECIDABLE 관찰 · 4 미관측 · 5 전체 바이트
        Map<ProtocolDecoder, long[]> perProtocol = new LinkedHashMap<>();
        for (ProtocolDecoder decoder : decoders) {
            perProtocol.put(decoder, new long[6]);
        }

        for (List<TcpStream> conversation : conversations(streams)) {
            List<ProtocolDecoder> claimers = new ArrayList<>();
            Map<ProtocolDecoder, List<StreamEvidence>> evidence = new LinkedHashMap<>();

            for (ProtocolDecoder decoder : decoders) {
                List<StreamEvidence> scanned = new ArrayList<>();
                boolean claims = false;
                for (TcpStream stream : conversation) {
                    StreamEvidence one = decoder.scan(stream);
                    scanned.add(one);
                    claims |= one.frameCount() > 0;
                }
                evidence.put(decoder, scanned);
                if (claims) {
                    claimers.add(decoder);
                }
            }

            // 대상 외가 절단·갭을 이긴다 — tcpdump -s 96 환경에서는 SSH 스트림도 전부 절단이라
            // 절단이 이기면 커버리지 지표가 비산업 트래픽에 지배된다.
            if (claimers.isEmpty()) {
                skipped++;
                continue;
            }
            if (claimers.size() > 1) {
                // 스트림 단위 불가능성은 대화 단위로 올라가지 못한다(설계 §3).
                // 등록 순서로 이기되 몇 번 일어났는지는 센다.
                multiClaim++;
            }

            ProtocolDecoder winner = claimers.get(0);
            List<StreamEvidence> conversationEvidence = evidence.get(winner);

            long[] mine = perProtocol.get(winner);

            // 대상 외로 빠져나간 뒤에 센다 — 배제가 규칙이 아니라 구조로 지켜진다.
            for (StreamEvidence one : conversationEvidence) {
                long unread = one.unreadBytes() + one.stream().missingBytes();
                long total = one.capturedBytes() + one.stream().missingBytes();
                unobserved += unread;
                industrial += total;
                mine[4] += unread;
                mine[5] += total;
                rejectedRuns += one.rejectedRuns();
                dirtyRuns += one.dirtyRuns();
            }

            Decoded result = winner.decode(conversationEvidence);
            if (result.bothDirectionsRequested()) {
                bothDirections++;
            }

            // 아래 셋은 순서 있는 사슬이며 먼저 맞는 것이 이긴다.
            if (result.client() == null) {
                // 판정 불가. 여기서 대화를 끝낸다 — 이어 돌면 관찰 두 건과 이중 계수가 난다.
                observations.add(undecidableOf(conversationEvidence.get(0).stream(), winner));
                undecidable++;
                mine[1]++;
                mine[2]++;
                mine[3]++;
            } else if (result.requestObservations().isEmpty()) {
                // 클라이언트 방향에서 프레임을 못 뽑았다. 이 갈래가 없으면 대화가 어디에도 안 세인다.
                observations.add(undecidableOf(result.client().stream(), winner));
                undecidable++;
                mine[1]++;
                mine[2]++;
                mine[3]++;
            } else {
                observations.addAll(result.requestObservations());
                decoded++;
                mine[0]++;
                mine[2] += result.requestObservations().size();
                for (Observation one : result.requestObservations()) {
                    if (one.access() == Access.UNDECIDABLE) {
                        mine[3]++;
                    }
                }

                // 관찰은 나왔지만 다 봤다고 말하면 안 되는 경우. 대화 계수는 더 건드리지 않는다.
                // 꼬리 관찰의 주소는 언제나 client 것이다 — tailUndecidable 이 서버 방향의
                // 사건(Userdata·COTP 분할)에서 비롯됐더라도 그렇다.
                StreamEvidence client = result.client();
                if (client.unreadBytes() > 0 || client.stream().hasGap()
                    || client.stream().truncated() || result.tailUndecidable()) {
                    observations.add(undecidableOf(client.stream(), winner));
                    mine[2]++;
                    mine[3]++;
                }
            }
        }

        List<ProtocolCoverage> byProtocol = new ArrayList<>();
        for (Map.Entry<ProtocolDecoder, long[]> entry : perProtocol.entrySet()) {
            long[] c = entry.getValue();
            byProtocol.add(new ProtocolCoverage(entry.getKey().protocol(),
                (int) c[0], (int) c[1], (int) c[2], (int) c[3], c[4], c[5]));
        }

        return new Diagnosed(
            new ObservationResult(List.copyOf(observations), decoded, undecidable, skipped,
                unobserved, industrial, List.copyOf(byProtocol)),
            multiClaim, bothDirections, rejectedRuns, dirtyRuns);
    }

    /**
     * 4-tuple 을 뒤집어 스트림을 대화로 묶는다. 키는 두 (주소, 포트) 쌍을 정렬한 것이라 방향에
     * 무관하고, 포트가 다르면 다른 키이므로 같은 호스트 쌍의 연결 둘은 합쳐지지 않는다.
     * 순회 순서는 각 대화가 입력 목록에 처음 등장한 순서다 — 결정성은 완료 조건이다.
     */
    private static List<List<TcpStream>> conversations(List<TcpStream> streams) {
        Map<String, List<TcpStream>> byPair = new LinkedHashMap<>();
        for (TcpStream stream : streams) {
            byPair.computeIfAbsent(conversationKey(stream), k -> new ArrayList<>()).add(stream);
        }
        return List.copyOf(byPair.values());
    }

    private static String conversationKey(TcpStream stream) {
        String one = stream.sourceAddress() + ":" + stream.sourcePort();
        String other = stream.targetAddress() + ":" + stream.targetPort();
        return one.compareTo(other) <= 0 ? one + "|" + other : other + "|" + one;
    }

    /** 무엇을 건드렸는지 모르므로 objectRef 는 "-" 다. 지어내면 근거가 아니라 추측이 된다. */
    private static Observation undecidableOf(TcpStream stream, ProtocolDecoder decoder) {
        return new Observation(
            stream.at(),
            new Endpoint(stream.sourceAddress(), stream.sourcePort()),
            new Endpoint(stream.targetAddress(), stream.targetPort()),
            decoder.protocol(),
            Access.UNDECIDABLE,
            "-");
    }
}
