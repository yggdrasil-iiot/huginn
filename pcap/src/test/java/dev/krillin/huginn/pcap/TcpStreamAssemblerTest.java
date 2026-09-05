package dev.krillin.huginn.pcap;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TcpStreamAssemblerTest {

    private static final String A = "10.0.1.20";
    private static final String B = "10.0.2.11";

    /** 전체형. syn=false·ack=true 인 데이터 세그먼트. at 은 seq 를 밀리초로 환산해 넣는다. */
    private TcpSegment seg(String src, int sport, String dst, int dport,
                            long seq, String payload, boolean truncated) {
        return new TcpSegment(Instant.ofEpochMilli(seq), src, sport, dst, dport, seq,
            payload.getBytes(StandardCharsets.US_ASCII), truncated, false, true);
    }

    /** 축약형 — A:40000 → B:502 고정, truncated=false. */
    private TcpSegment seg(long seq, String payload) {
        return seg(A, 40000, B, 502, seq, payload, false);
    }

    /** 같은 고정 4-tuple 의 길이 0 세그먼트, syn=true·ack=false. */
    private TcpSegment syn(long seq) {
        return new TcpSegment(Instant.ofEpochMilli(seq), A, 40000, B, 502, seq,
            new byte[0], false, true, false);
    }

    /** 같은 고정 4-tuple 의 길이 0 세그먼트, syn=true·ack=true. */
    private TcpSegment synAck(long seq) {
        return new TcpSegment(Instant.ofEpochMilli(seq), A, 40000, B, 502, seq,
            new byte[0], false, true, true);
    }

    private List<TcpStream> assembleAll(TcpSegment... segs) {
        return TcpStreamAssembler.assemble(List.of(segs));
    }

    private TcpStream assemble(TcpSegment... segs) {
        return assembleAll(segs).get(0);
    }

    @Test
    void 순서대로_온_세그먼트를_이어붙인다() {
        TcpStream s = assemble(seg(100, "abc"), seg(103, "def"));
        assertFalse(s.hasGap());
        assertArrayEquals("abcdef".getBytes(), s.contiguousPrefix());
    }

    @Test
    void 순서가_뒤바뀌어도_seq로_정렬한다() {
        // at 도 함께 못박는다 — "입력 순서상 첫 번째" 로 구현하면 여기서 뒤집힌다.
        TcpStream s = assemble(seg(103, "def"), seg(100, "abc"));
        assertArrayEquals("abcdef".getBytes(), s.contiguousPrefix());
        assertEquals(seg(100, "abc").at(), s.at(), "가장 이른 시각이지 입력 순서상 첫 번째가 아니다");
    }

    @Test
    void SYN을_보면_바이트는_버리되_sawSynOnly를_기록한다() {
        // 길이 0 세그먼트를 통째로 버리면 연결을 연 쪽을 확정할 유일한 신호가 사라진다.
        TcpStream s = assemble(syn(1000), seg(1001, "abc"));
        assertTrue(s.sawSynOnly());
        // 그리고 SYN 의 seq 가 base 후보로 새어 들어가면 안 된다. 들어가면 base=1000 이 되어
        // 데이터가 오프셋 1 에 놓이고 1바이트 갭이 난다 — 길이 0 제외 규칙이 무력화된다.
        assertFalse(s.hasGap());
        assertArrayEquals("abc".getBytes(), s.contiguousPrefix());
    }

    @Test
    void SYN_ACK는_sawSynOnly가_아니다() {
        // SYN+ACK 도 SYN 비트가 서 있다. syn 만 보면 서버 방향에도 플래그가 서고,
        // 핸드셰이크가 잡힌 모든 대화에서 양쪽이 같아져 청크 3 의 1순위 근거가 무력해진다.
        assertFalse(assemble(synAck(7000), seg(7001, "abc")).sawSynOnly());
    }

    @Test
    void SYN만_있고_데이터가_없는_스트림도_정의된_값을_낸다() {
        // base seq 후보가 하나도 없다. 예외가 아니라 빈 스트림이어야 한다.
        TcpStream s = assemble(syn(1000));
        assertTrue(s.sawSynOnly());
        assertEquals(0, s.contiguousPrefix().length);
        assertFalse(s.hasGap());
        assertEquals(syn(1000).at(), s.at(), "at 후보가 없으면 null 이 되어서는 안 된다");
    }

    @Test
    void 길이_0_세그먼트는_조립에서_제외한다() {
        // SYN 은 seq 를 1 소비한다. 제외하지 않으면 핸드셰이크가 잡힌 모든 스트림이
        // 1바이트 갭 → 전량 UNDECIDABLE 이 된다.
        TcpStream s = assemble(seg(1000, ""), seg(1001, "abc"));
        assertFalse(s.hasGap());
        assertArrayEquals("abc".getBytes(), s.contiguousPrefix());
    }

    @Test
    void 방향마다_별개_스트림이다() {
        List<TcpStream> streams = assembleAll(
            seg(A, 40000, B, 502, 100, "req", false),
            seg(B, 502, A, 40000, 7000, "res", false));
        assertEquals(2, streams.size());
    }

    @Test
    void 갭이_있으면_그_지점부터_UNDECIDABLE이다() {
        // 조용히 이어붙이면 프레임 경계가 어긋나 엉뚱한 함수코드를 읽는다.
        TcpStream s = assemble(seg(100, "abc"), seg(200, "xyz"));
        assertTrue(s.hasGap());
        assertArrayEquals("abc".getBytes(), s.contiguousPrefix());
    }

    @Test
    void 캡처가_대화_중간부터_시작해도_최소_seq를_기준으로_삼는다() {
        TcpStream s = assemble(seg(500000, "abc"), seg(500003, "def"));
        assertFalse(s.hasGap());
        assertArrayEquals("abcdef".getBytes(), s.contiguousPrefix());
    }

    @Test
    void 완전_중복_세그먼트는_한_번만_반영한다() {
        TcpStream s = assemble(seg(100, "abc"), seg(100, "abc"));
        assertFalse(s.hasGap());
        assertArrayEquals("abc".getBytes(), s.contiguousPrefix());
    }

    @Test
    void 겹치는_재전송은_먼저_온_바이트가_이긴다() {
        // 나중 세그먼트로 앞 내용을 덮어쓸 수 있으면 재전송 위장으로 판정을 속일 수 있다.
        // base=100. 첫 세그먼트가 오프셋 0~4, 둘째는 2~6 을 차지한다.
        // 2·3·4 는 이미 찼으므로 지고, 5·6 만 X 가 된다 → 7바이트.
        TcpStream s = assemble(seg(100, "abcde"), seg(102, "XXXXX"));
        assertArrayEquals("abcdeXX".getBytes(), s.contiguousPrefix());
    }

    @Test
    void 절단된_세그먼트가_있으면_스트림을_절단으로_표시한다() {
        assertTrue(assemble(seg(A, 40000, B, 502, 100, "abc", true)).truncated());
    }

    @Test
    void 스트림_열거_순서는_최초_등장_순서다() {
        // HashMap 이면 리포트가 비결정적이 된다. 비결정성의 발원지가 이 층이다.
        // 이 네 방향(A:40000<->B:502, A:40001<->B:502)은 HashMap 반복 순서가 삽입 순서와
        // 실제로 어긋나는 조합이다 — 직접 LinkedHashMap/HashMap 에 넣어 반복 순서를 찍어
        // 확인했다. 방향이 둘뿐이던 이전 버전은 우연히 두 순서가 같아 회귀를 못 잡았다.
        // 그러니 방향 수를 줄이거나 주소·포트를 바꾸지 말 것 — 이 보장이 다시 사라진다.
        List<TcpStream> streams = assembleAll(
            seg(A, 40000, B, 502, 100, "req0", false),
            seg(B, 502, A, 40000, 7000, "res0", false),
            seg(A, 40001, B, 502, 200, "req1", false),
            seg(B, 502, A, 40001, 8000, "res1", false));

        List<String> actual = streams.stream()
            .map(s -> s.sourceAddress() + ":" + s.sourcePort() + "->" + s.targetAddress() + ":" + s.targetPort())
            .toList();
        assertEquals(List.of(
            A + ":40000->" + B + ":502",
            B + ":502->" + A + ":40000",
            A + ":40001->" + B + ":502",
            B + ":502->" + A + ":40001"), actual);
    }

    @Test
    void 같은_입력에_같은_스트림_목록이_나온다() {
        // TcpStream 은 byte[] 컴포넌트를 가진 record 라 자동 생성 equals 가 배열을 **동등성이 아니라
        // 동일성**으로 비교한다. assertEquals(assemble(x), assemble(x)) 는 항상 실패한다.
        // 4-tuple 순서를 먼저 비교하고 바이트는 assertArrayEquals 로 따로 본다.
        TcpSegment[] input = {
            seg(A, 40000, B, 502, 100, "abc", false),
            seg(B, 502, A, 40000, 7000, "res", false),
            seg(A, 40000, B, 502, 103, "def", false)};
        List<TcpStream> a = assembleAll(input);
        List<TcpStream> b = assembleAll(input);
        assertEquals(2, a.size(), "스트림이 하나뿐이면 아래 비교가 자명하게 통과해 아무것도 검증하지 못한다");
        assertEquals(a.stream().map(TcpStream::sourcePort).toList(),
            b.stream().map(TcpStream::sourcePort).toList());
        for (int i = 0; i < a.size(); i++)
            assertArrayEquals(a.get(i).contiguousPrefix(), b.get(i).contiguousPrefix());
    }
}
