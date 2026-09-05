package dev.krillin.huginn.decode;

import dev.krillin.huginn.pcap.TcpStream;
import dev.krillin.huginn.reconcile.Access;
import dev.krillin.huginn.reconcile.Observation;
import dev.krillin.huginn.reconcile.Protocol;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;

import static dev.krillin.huginn.decode.ModbusFixtures.concat;
import static dev.krillin.huginn.decode.ModbusFixtures.mbap;
import static dev.krillin.huginn.decode.ModbusFixtures.pdu;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ModbusObserverTest {

    /** 전체형. 청크 2 의 PcapBuilder 는 pcap 모듈 테스트 소스라 여기서 보이지 않으므로 직접 만든다. */
    private static TcpStream stream(String src, int sport, String dst, int dport, byte[] bytes,
                                    Instant at, boolean sawSynOnly, boolean hasGap, boolean truncated) {
        return new TcpStream(at, src, sport, dst, dport, bytes, hasGap, truncated, sawSynOnly);
    }

    /** 흔한 경우의 축약 — at 은 EPOCH, 플래그는 전부 false. */
    private static TcpStream stream(String src, int sport, String dst, int dport, byte[] bytes) {
        return stream(src, sport, dst, dport, bytes, Instant.EPOCH, false, false, false);
    }

    private ObservationResult observe(TcpStream... streams) {
        return ModbusObserver.observe(List.of(streams));
    }

    private final TcpStream requestStream =                 // hmi:40000 → plc:502, FC 3 한 프레임
        stream("10.0.1.20", 40000, "10.0.2.11", 502, mbap(1, 1, 3, pdu(0, 2)));
    private final TcpStream responseStream =                // plc:502 → hmi:40000, FC 3 응답
        stream("10.0.2.11", 502, "10.0.1.20", 40000, mbap(1, 1, 3, new byte[]{4, 0, 0, 0, 0}));
    private final TcpStream responseOnlyStream = responseStream;   // 짝이 없는 단독 스트림
    private final TcpStream sshStream =
        stream("10.0.1.20", 40000, "10.0.3.5", 22,
            "SSH-2.0-OpenSSH_9.0\r\n".getBytes(StandardCharsets.US_ASCII));
    private final TcpStream truncatedSshStream =
        stream("10.0.1.20", 40000, "10.0.3.5", 22,
            "SSH-2.0-OpenSSH_9.0\r\n".getBytes(StandardCharsets.US_ASCII),
            Instant.EPOCH, false, false, true);

    @Test
    void 요청만_Observation이_된다() {
        // 요청 hmi→plc(FC 3)와 응답 plc→hmi(FC 3)가 모두 있는 대화.
        // 응답까지 관찰하면 출발지·목적지가 뒤집혀 정상 통신이 위반이 된다.
        ObservationResult r = observe(requestStream, responseStream);
        assertEquals(1, r.observations().size());
        assertEquals("10.0.1.20", r.observations().get(0).source().address());
    }

    @Test
    void 관찰_시각은_스트림의_가장_이른_세그먼트_시각이다() {
        // 입력 순서상 첫 번째가 아니다 — 청크 2 TcpStream.at 이 시각 기준으로 이미 정해져 있다.
        Instant clientAt = Instant.ofEpochMilli(9_000);
        TcpStream client = stream("10.0.1.20", 40000, "10.0.2.11", 502, mbap(1, 1, 3, pdu(0, 2)),
            clientAt, false, false, false);
        TcpStream server = stream("10.0.2.11", 502, "10.0.1.20", 40000,
            mbap(1, 1, 3, new byte[]{4, 0, 0, 0, 0}), Instant.ofEpochMilli(1_000), false, false, false);

        ObservationResult r = observe(server, client);

        assertEquals(1, r.observations().size());
        assertEquals(clientAt, r.observations().get(0).at());
    }

    @Test
    void 한_스트림의_프레임_여러_개가_각각_관찰이_된다() {
        ObservationResult r = observe(stream("10.0.1.20", 40000, "10.0.2.11", 502, concat(
            mbap(1, 1, 3, pdu(0, 2)),                                   // 읽기 요청
            mbap(2, 1, 16, new byte[]{0, 99, 0, 2, 4, 0, 1, 0, 2}))));  // 다중 쓰기 요청

        assertEquals(2, r.observations().size());
        assertEquals(1, r.decodedConversations());

        Observation read = r.observations().get(0);
        assertEquals(Access.READ, read.access());
        assertEquals("holding:40001", read.objectRef());
        assertEquals(Protocol.MODBUS_TCP, read.protocol());

        Observation write = r.observations().get(1);
        assertEquals(Access.WRITE, write.access());
        assertEquals("holding:40100", write.objectRef());
    }

    @Test
    void Modbus가_아닌_스트림은_관찰도_미해독도_아니다() {
        // SSH 스트림 하나만 있는 캡처 → 관찰 0, UNDECIDABLE 0, 대상 외 1
        ObservationResult r = observe(sshStream);
        assertTrue(r.observations().isEmpty());
        assertEquals(0, r.decodedConversations());
        assertEquals(0, r.undecidableConversations());
        assertEquals(1, r.skippedConversations());
    }

    @Test
    void 대화_수는_세_계수의_합과_같다() {
        // 응답 방향 스트림은 Modbus 이지만 관찰을 만들지 않는다. 어느 칸에도 안 세면
        // 해독한 대화 6 이 6 인지 12 인지 알 수 없고 합이 맞지 않는다.
        ObservationResult r = observe(requestStream, responseStream, sshStream);
        assertEquals(2, r.decodedConversations() + r.undecidableConversations() + r.skippedConversations());
        assertEquals(1, r.decodedConversations());
        assertEquals(1, r.skippedConversations());
    }

    @Test
    void Modbus_스트림_안의_미해독_바이트는_UNDECIDABLE_관찰을_만든다() {
        byte[] withGarbage = concat(mbap(1, 1, 3, pdu(0, 2)),
            "GET / HTTP/1.1\r\n".getBytes(StandardCharsets.US_ASCII));

        ObservationResult r = observe(stream("10.0.1.20", 40000, "10.0.2.11", 502, withGarbage));

        assertEquals(2, r.observations().size(), "프레임 관찰 1 + 잔여 바이트 관찰 1");
        assertEquals(Access.READ, r.observations().get(0).access());
        assertEquals(Access.UNDECIDABLE, r.observations().get(1).access());
        assertEquals("-", r.observations().get(1).objectRef());
        assertEquals(1, r.decodedConversations());
        assertEquals(0, r.undecidableConversations(), "대화는 해독이다 — 관찰 단위와 섞지 않는다");
    }

    @Test
    void 갭이_있는_스트림은_연속_구간만_해독하고_나머지는_UNDECIDABLE이다() {
        // 재조립이 연속 구간만 넘겨준다. 뒤가 비었다는 사실을 관찰로 남기지 않으면 다 봤다가 된다.
        ObservationResult r = observe(
            stream("10.0.1.20", 40000, "10.0.2.11", 502, mbap(1, 1, 3, pdu(0, 2)),
                Instant.EPOCH, false, /* hasGap */ true, false),
            responseStream);

        assertEquals(2, r.observations().size(), "프레임 관찰 1 + 갭 관찰 1");
        assertEquals(Access.UNDECIDABLE, r.observations().get(1).access());
        assertEquals(1, r.decodedConversations());
        assertEquals(0, r.undecidableConversations());
    }

    @Test
    void 형태를_모르면_SYN이_결정한다() {
        // FC 6 은 응답이 요청의 에코라 양쪽 다 UNKNOWN → S2 미성립. S1 만 남는다.
        // 포트는 40000 → 502 를 가리키지만 SYN 은 502 쪽에 서 있다(포트 재사용·비표준 배치).
        // 포트를 보는 구현이 남아 있으면 여기서 갈린다.
        ObservationResult r = observe(
            stream("10.0.2.11", 502, "10.0.1.20", 40000, mbap(1, 1, 6, pdu(0, 42)),
                Instant.EPOCH, /* sawSynOnly */ true, false, false),
            stream("10.0.1.20", 40000, "10.0.2.11", 502, mbap(1, 1, 6, pdu(0, 42)),
                Instant.EPOCH, /* sawSynOnly */ false, false, false));
        assertEquals(1, r.observations().size());
        assertEquals("10.0.2.11", r.observations().get(0).source().address());
    }

    @Test
    void SYN과_형태가_어긋나면_판정하지_않는다() {
        // 조립기는 4-tuple 만으로 키를 잡고 연결 경계를 모른다. 502↔502 게이트웨이 쌍에서
        // X 가 연 유휴 연결의 SYN 과, Y 가 연 다른 연결의 데이터가 한 대화로 묶인다.
        // SYN 은 X→Y 를, 형태는 Y→X 를 가리킨다 — 그리고 형태가 옳다.
        ObservationResult r = observe(
            stream("10.0.1.30", 502, "10.0.2.11", 502,
                mbap(7, 1, 16, new byte[]{0, 100, 0, 1}),                 // RESPONSE_ONLY
                Instant.EPOCH, /* sawSynOnly */ true, false, false),
            stream("10.0.2.11", 502, "10.0.1.30", 502,
                mbap(7, 1, 16, new byte[]{0, 100, 0, 1, 2, 0, 5}),        // REQUEST_ONLY
                Instant.EPOCH, /* sawSynOnly */ false, false, false));
        assertEquals(1, r.observations().size());
        assertEquals(Access.UNDECIDABLE, r.observations().get(0).access());
        assertEquals(1, r.undecidableConversations());
    }

    @Test
    void SYN이_없으면_형태가_결정한다() {
        // 대화 중간부터 시작한 표준 배치. 요청 방향은 4바이트 FC 3(REQUEST_ONLY),
        // 응답 방향은 5바이트(RESPONSE_ONLY) — 포트를 보지 않고 갈린다.
        ObservationResult r = observe(requestStream, responseStream);
        assertEquals(1, r.observations().size());
        assertEquals("10.0.1.20", r.observations().get(0).source().address());
        assertEquals(Access.READ, r.observations().get(0).access());
    }

    @Test
    void 양쪽이_같은_형태면_대화가_잘못_묶인_것이라_판정하지_않는다() {
        // 한 대화에서 양쪽이 모두 요청일 수 없다. 한 4-tuple 에 연결이 둘 묶였거나
        // 재조립이 어긋난 것이다. 다수결로 밀어붙이지 않는다.
        ObservationResult r = observe(
            stream("10.0.1.30", 502, "10.0.2.11", 502, mbap(1, 1, 3, pdu(0, 2))),
            stream("10.0.2.11", 502, "10.0.1.30", 502, mbap(2, 1, 3, pdu(0, 4))));
        assertEquals(1, r.observations().size());
        assertEquals(Access.UNDECIDABLE, r.observations().get(0).access());
        assertEquals(1, r.undecidableConversations());
    }

    @Test
    void 한_방향만_잡힌_캡처는_요청으로_단정하지_않는다() {
        // 서버→클라이언트만 잡힌 캡처를 요청으로 읽으면 응답의 FC 16 이 WRITE 가 되고
        // PLC 가 미등록 출발지가 되어 HIGH 오탐이 난다. 이 청크 개정의 핵심 가드다.
        ObservationResult r = observe(responseOnlyStream);
        // allMatch 만 두면 관찰을 0건 내는 구현도 통과한다 — 크기를 먼저 못박는다.
        assertEquals(1, r.observations().size());
        assertEquals(Access.UNDECIDABLE, r.observations().get(0).access());
        assertEquals(1, r.undecidableConversations());
        assertEquals(0, r.decodedConversations());
    }

    @Test
    void 양쪽_다_임시_포트면_판정_불가다() {
        // 비표준 고포트 우회 + 단방향 캡처. 낮은 포트가 서버라는 규칙만 두면 낮은 쪽이
        // 49500(클라이언트)이라 서버 방향이 클라이언트로 지목되고, FC 16 응답이 WRITE 가 되어
        // PLC 가 미등록 출발지로 HIGH 오탐이 난다. 하필 이 도구가 가장 잡아야 할 대상이다.
        ObservationResult r = observe(
            stream("10.0.2.11", 55000, "10.0.1.20", 49500,
                mbap(1, 1, 16, new byte[]{0, 0, 0, 2})));   // FC 16 응답
        assertEquals(1, r.observations().size());
        assertEquals(Access.UNDECIDABLE, r.observations().get(0).access());
        assertEquals(1, r.undecidableConversations());
    }

    @Test
    void 서버_포트가_더_높아도_형태로_판정한다() {
        // 거울상 가드 ①. 클라 1288(WinCE HMI 임시 포트) / 서버 50502.
        // 양방향이 다 잡혀 있어 단방향 가드(R5)가 구제하지 못한다.
        // S2(형태)가 포트를 보지 않고 9바이트 요청 / 4바이트 응답으로 갈라 준다.
        ObservationResult r = observe(
            stream("10.0.1.20", 1288, "10.0.2.11", 50502,
                mbap(1, 1, 16, new byte[]{0, 0, 0, 2, 4, 0, 1, 0, 2})),
            stream("10.0.2.11", 50502, "10.0.1.20", 1288,
                mbap(1, 1, 16, new byte[]{0, 0, 0, 2})));
        assertEquals(1, r.observations().size());
        assertEquals("10.0.1.20", r.observations().get(0).source().address());
        assertEquals(Access.WRITE, r.observations().get(0).access());
        assertEquals(1, r.decodedConversations());
    }

    @Test
    void 형태를_모르고_SYN도_없으면_판정_불가다() {
        // FC 6 에코만 오가고 핸드셰이크도 못 잡은 대화. 두 신호가 다 침묵한다.
        // 여기서 포트를 보면 안 된다 — 이 배치는 클라 502(방화벽 통과용 바인드) /
        // 서버 55000(비표준 포트 우회)이라 낮은 쪽이 서버라는 규칙이 정확히 뒤집힌다.
        ObservationResult r = observe(
            stream("10.0.1.30", 502, "10.0.2.11", 55000, mbap(1, 1, 6, pdu(0, 42))),
            stream("10.0.2.11", 55000, "10.0.1.30", 502, mbap(1, 1, 6, pdu(0, 42))));
        assertEquals(1, r.observations().size());
        assertEquals(Access.UNDECIDABLE, r.observations().get(0).access());
        assertEquals(1, r.undecidableConversations());
        assertEquals(0, r.decodedConversations());
    }

    @Test
    void 클라이언트가_특권_포트를_바인딩해도_형태로_판정한다() {
        // 502↔502 만 허용하는 방화벽을 지나려고 로컬 포트 502 를 바인딩한 클라이언트.
        // 포트를 보는 규칙은 502 를 서버로 단정해 40000→502 응답 방향을 클라이언트로 읽는다.
        ObservationResult r = observe(
            stream("10.0.2.11", 40000, "10.0.1.30", 502,
                mbap(1, 1, 16, new byte[]{0, 0, 0, 2})),                          // 응답 형태
            stream("10.0.1.30", 502, "10.0.2.11", 40000,
                mbap(1, 1, 16, new byte[]{0, 0, 0, 2, 4, 0, 1, 0, 2})));          // 요청 형태
        assertEquals(1, r.observations().size());
        assertEquals("10.0.1.30", r.observations().get(0).source().address());
        assertEquals(Access.WRITE, r.observations().get(0).access());
    }

    @Test
    void 절단된_비Modbus_스트림은_대상_외가_이긴다() {
        // tcpdump -s 96 환경에서는 SSH 스트림도 전부 절단이다.
        // 절단이 이기면 커버리지 지표가 다시 비산업 트래픽에 지배된다.
        ObservationResult r = observe(truncatedSshStream);
        assertEquals(0, r.undecidableConversations());
        assertEquals(1, r.skippedConversations());
    }

    @Test
    void 판정_불가_대화는_UNDECIDABLE_관찰을_한_건만_남긴다() {
        // 판정 불가이면서 절단이기도 한 스트림 — 단방향 캡처는 보통 SPAN·snaplen 산물이라
        // 이 조합이 오히려 흔하다. 판정 불가에서 끝내지 않으면 잔여·절단 처리가 한 번 더 돌아
        // 관찰 두 건, undecidableConversations 도 2 가 된다.
        ObservationResult r = observe(
            stream("10.0.2.11", 502, "10.0.1.20", 40000, mbap(1, 1, 3, new byte[]{4, 0, 0, 0, 0}),
                Instant.EPOCH, false, false, /* truncated */ true));
        assertEquals(1, r.observations().size());
        assertEquals(1, r.undecidableConversations());
    }

    @Test
    void 해독한_대화의_절단은_UNDECIDABLE_관찰을_함께_남긴다() {
        // 프레임은 뽑혔지만 뒤가 잘렸다. 관찰은 나오되 다 봤다고 말하면 안 된다.
        ObservationResult r = observe(
            stream("10.0.1.20", 40000, "10.0.2.11", 502, mbap(1, 1, 3, pdu(0, 2)),
                Instant.EPOCH, false, false, /* truncated */ true),
            responseStream);
        assertEquals(2, r.observations().size(), "프레임 관찰 1 + 절단 관찰 1");
        assertEquals(1, r.decodedConversations());
        assertEquals(0, r.undecidableConversations(), "대화는 해독이다 — 관찰 단위와 섞지 않는다");
    }

    @Test
    void 클라이언트_방향만_프레임을_못_뽑은_대화도_어딘가에_센다() {
        // 클라이언트 스트림이 프레임 중간에서 시작해 재동기화를 하지 않으므로 프레임 0개,
        // 서버 스트림은 마침 경계에서 시작해 정상. 서버 방향만 RESPONSE_ONLY 라 S2 가 성립해
        // 반대 방향을 지목하고, 그 방향도 캡처에 있으니 R5 가 발동하지 않는다.
        // 여기서 종결 규칙이 없으면 이 대화가 세 계수 어디에도 안 세인다.
        ObservationResult r = observe(
            stream("10.0.1.20", 40000, "10.0.2.11", 502, "쓰레기 바이트".getBytes(StandardCharsets.UTF_8)),
            stream("10.0.2.11", 502, "10.0.1.20", 40000, mbap(1, 1, 3, new byte[]{4, 0, 0, 0, 0})));
        assertEquals(0, r.decodedConversations());
        assertEquals(1, r.undecidableConversations());
        assertEquals(1, r.decodedConversations() + r.undecidableConversations() + r.skippedConversations());
    }
}
