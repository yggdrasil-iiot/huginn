package dev.krillin.huginn.decode;

import dev.krillin.huginn.pcap.TcpStream;
import dev.krillin.huginn.reconcile.Access;
import dev.krillin.huginn.reconcile.Protocol;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;

import static dev.krillin.huginn.decode.S7Fixtures.sym;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 해독기 단독이 아니라 {@link TrafficObserver} 까지 함께 돌린다 — 계수 규칙이 그쪽에 있다.
 */
class S7DecoderTest {

    private static final String HMI = "10.0.1.20";
    private static final String PLC = "10.0.2.11";
    private static final String A = "10.0.1.30";
    private static final String B = "10.0.2.40";

    private static final byte[] READ_JOB = S7Fixtures.job(S7Fixtures.readVar(sym(0, 0x52, 16)));
    private static final byte[] READ_ACK =
        S7Fixtures.ackData(new byte[]{0x04, 0x01}, new byte[]{(byte) 0xFF, 4, 0, 2, 0, 1});
    private static final byte[] USERDATA = S7Fixtures.userdata(new byte[]{0x00, 0x01, 0x12, 0x04});

    private static TcpStream stream(String src, int sport, String dst, int dport, byte[] bytes) {
        return new TcpStream(Instant.EPOCH, src, sport, dst, dport, bytes, false, false, false);
    }

    private ObservationResult observe(TcpStream... streams) {
        return TrafficObserver.observe(List.of(streams), List.of(new S7Decoder()));
    }

    private Diagnosed observeWithDiagnostics(TcpStream... streams) {
        return TrafficObserver.observeWithDiagnostics(List.of(streams), List.of(new S7Decoder()));
    }

    @Test
    void 요청만_관찰한다() {
        // Job 은 hmi→plc, Ack_Data 는 plc→hmi. 응답까지 관찰하면 정상 통신이 위반이 된다.
        ObservationResult r = observe(
            stream(HMI, 2000, PLC, 102, READ_JOB),
            stream(PLC, 102, HMI, 2000, READ_ACK));

        assertEquals(1, r.observations().size());
        assertEquals(HMI, r.observations().get(0).source().address());
        assertEquals(Access.READ, r.observations().get(0).access());
        assertEquals(Protocol.S7COMM, r.observations().get(0).protocol());
        assertEquals("sym:m/16", r.observations().get(0).objectRef());
        assertEquals(1, r.decodedConversations());
    }

    @Test
    void 응답만_잡힌_캡처는_판정하지_않는다() {
        // 1차 R5 에 해당하는 경우인데 S7 에는 별도 가드가 없다 — 요청 방향이 0 개라 자동으로 걸린다.
        ObservationResult r = observe(stream(PLC, 102, HMI, 2000, READ_ACK));

        assertEquals(1, r.observations().size());
        assertEquals(Access.UNDECIDABLE, r.observations().get(0).access());
        assertEquals(1, r.undecidableConversations());
        assertEquals(0, r.decodedConversations());
    }

    @Test
    void 양쪽_방향에_모두_요청이_있으면_판정하지_않는다() {
        // 한 4-tuple 에 연결이 둘 묶였거나 재조립이 어긋난 것이다. 다수결로 밀어붙이지 않는다.
        Diagnosed d = observeWithDiagnostics(
            stream(A, 102, B, 102, READ_JOB),
            stream(B, 102, A, 102, READ_JOB));

        assertEquals(1, d.result().observations().size());
        assertEquals(Access.UNDECIDABLE, d.result().observations().get(0).access());
        assertEquals(1, d.result().undecidableConversations());
        assertEquals(1, d.bothDirectionRequestConversations(), "요청 방향이 0 개인 경우와 구별된다");
    }

    @Test
    void 응답만_잡힌_경우는_양방향_요청으로_세지_않는다() {
        // 위 테스트의 짝. 둘 다 client == null 이지만 원인이 다르다.
        Diagnosed d = observeWithDiagnostics(stream(PLC, 102, HMI, 2000, READ_ACK));

        assertEquals(1, d.result().undecidableConversations());
        assertEquals(0, d.bothDirectionRequestConversations());
    }

    @Test
    void Userdata만_실린_대화는_UNDECIDABLE_대화다() {
        // 프레임으로는 세므로 대상 외가 아니다. 그러나 요청 방향이 0 개라 관찰이 없다.
        ObservationResult r = observe(stream(HMI, 2000, PLC, 102, USERDATA));

        assertEquals(1, r.observations().size());
        assertEquals(Access.UNDECIDABLE, r.observations().get(0).access());
        assertEquals(1, r.undecidableConversations());
        assertEquals(0, r.skippedConversations());
    }

    @Test
    void Job과_Userdata가_섞이면_해독하고_꼬리를_하나_남긴다() {
        // Userdata 가 몇 개든 꼬리는 한 건이다 — 프레임 수와 무관하다(설계 §5).
        ObservationResult r = observe(stream(HMI, 2000, PLC, 102,
            S7Fixtures.concat(READ_JOB, USERDATA, USERDATA)));

        assertEquals(2, r.observations().size(), "Job 관찰 1 + 꼬리 1");
        assertEquals(Access.READ, r.observations().get(0).access());
        assertEquals(Access.UNDECIDABLE, r.observations().get(1).access());
        assertEquals("-", r.observations().get(1).objectRef());
        assertEquals(1, r.decodedConversations());
        assertEquals(0, r.undecidableConversations());
    }

    @Test
    void 응답_방향의_Userdata도_꼬리를_만든다() {
        // client 의 잔여만 보는 규칙으로는 못 잡는 경우 — tailUndecidable 이 존재하는 이유다.
        ObservationResult r = observe(
            stream(HMI, 2000, PLC, 102, READ_JOB),
            stream(PLC, 102, HMI, 2000, USERDATA));

        assertEquals(2, r.observations().size(), "Job 관찰 1 + 꼬리 1");
        assertEquals(Access.UNDECIDABLE, r.observations().get(1).access());
        assertEquals(HMI, r.observations().get(1).source().address(), "꼬리 주소는 언제나 client 것이다");
        assertEquals(1, r.decodedConversations());
    }

    @Test
    void COTP_분할도_꼬리를_만든다() {
        // 분할은 재조립하지 않는다(설계 §2). 그러나 못 본 것이 있다는 사실은 남긴다.
        ObservationResult r = observe(stream(HMI, 2000, PLC, 102, S7Fixtures.concat(
            READ_JOB, S7Fixtures.fragmented(S7Fixtures.readVar(sym(0, 0x52, 17))))));

        assertEquals(2, r.observations().size(), "Job 관찰 1 + 꼬리 1");
        assertEquals(Access.UNDECIDABLE, r.observations().get(1).access());
        assertEquals(1, r.decodedConversations());
    }

    @Test
    void 연결설정만_오간_대화는_대상_외다() {
        ObservationResult r = observe(stream(HMI, 2000, PLC, 102, S7Fixtures.connectRequest()));

        assertEquals(1, r.skippedConversations());
        assertTrue(r.observations().isEmpty());
    }

    @Test
    void 포트가_102가_아니어도_해독한다() {
        // S7 도 Modbus 와 같다 — 우회하는 사람은 포트를 바꾼다.
        ObservationResult r = observe(stream(HMI, 50001, PLC, 40102, READ_JOB));

        assertEquals(1, r.observations().size());
        assertEquals(Access.READ, r.observations().get(0).access());
        assertEquals(1, r.decodedConversations());
    }
}
