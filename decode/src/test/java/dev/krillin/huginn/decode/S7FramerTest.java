package dev.krillin.huginn.decode;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static dev.krillin.huginn.decode.S7Fixtures.sym;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class S7FramerTest {

    @Test
    void 유효한_Job_프레임을_뽑는다() {
        S7FramingResult r = S7Framer.frames(S7Fixtures.job(S7Fixtures.readVar(sym(0, 0x52, 16))));

        assertEquals(1, r.frames().size());
        assertEquals(1, r.frames().get(0).rosctr());
        assertEquals(0x04, r.frames().get(0).functionCode());
        assertEquals(0, r.undecodedBytes());
        assertFalse(r.fragmented());
    }

    @Test
    void 한_세그먼트의_TPKT_여러_개를_전부_뽑는다() {
        // 실캡처에 한 패킷당 PDU 가 여럿인 경우가 있다(tshark 가 쉼표로 나열하는 그것).
        S7FramingResult r = S7Framer.frames(S7Fixtures.concat(
            S7Fixtures.job(S7Fixtures.readVar(sym(0, 0x52, 16))),
            S7Fixtures.job(S7Fixtures.readVar(sym(0, 0x52, 17))),
            S7Fixtures.job(S7Fixtures.setupCommunication())));

        assertEquals(3, r.frames().size());
        assertEquals(0xF0, r.frames().get(2).functionCode());
        assertEquals(0, r.undecodedBytes());
    }

    @Test
    void 응답은_헤더가_12바이트다() {
        // ROSCTR 3 은 오류 클래스·코드가 더 붙는다. 10 으로 읽으면 길이 정합성이 깨져
        // 응답이 통째로 미해독이 되고, tshark 대조에서 응답 수가 안 맞는다.
        S7FramingResult r = S7Framer.frames(S7Fixtures.ackData(
            new byte[]{0x04, 0x01}, new byte[]{(byte) 0xFF, 4, 0, 2, 0, 1}));

        assertEquals(1, r.frames().size());
        assertEquals(3, r.frames().get(0).rosctr());
        assertEquals(0, r.undecodedBytes());
    }

    @Test
    void COTP_연결요청은_소비하되_세지_않는다() {
        // 이 테스트가 기대값 표의 존폐를 가른다 — 실제 클라이언트 스트림은 CR 로 시작한다.
        S7FramingResult r = S7Framer.frames(S7Fixtures.connectRequest());

        assertTrue(r.frames().isEmpty());
        assertEquals(0, r.undecodedBytes(), "우리 관심사가 아닌 프레임이지 미해독 바이트가 아니다");
    }

    @Test
    void 연결요청_뒤의_Job_을_정상적으로_뽑는다() {
        // 첫 비-S7 TPKT 에서 멈추는 구현이면 frameCount 가 0 이 되어 대화가 대상 외로 떨어지고
        // 실캡처의 Job 16만 개가 통째로 사라진다.
        S7FramingResult r = S7Framer.frames(S7Fixtures.concat(
            S7Fixtures.connectRequest(),
            S7Fixtures.job(S7Fixtures.readVar(sym(0, 0x52, 16))),
            S7Fixtures.job(S7Fixtures.readVar(sym(0, 0x52, 17)))));

        assertEquals(2, r.frames().size());
        assertEquals(0, r.undecodedBytes());
    }

    @Test
    void 페이로드가_0x32가_아니면_소비하되_세지_않는다() {
        // TPKT/COTP 는 ISO-on-TCP 일반 규약이라 S7 전용이 아니다.
        byte[] notS7 = S7Fixtures.tpkt(new byte[]{0x02, (byte) 0xF0, (byte) 0x80,
            0x33, 0x01, 0, 0, 0, 1, 0, 2, 0, 0});          // 0x33 — S7 이 아니다
        S7FramingResult r = S7Framer.frames(S7Fixtures.concat(
            notS7, S7Fixtures.job(S7Fixtures.readVar(sym(0, 0x52, 16)))));

        assertEquals(1, r.frames().size(), "S7 프레임만 센다");
        assertEquals(0, r.undecodedBytes(), "미해독이 아니라 관심사가 아닌 프레임이다");
    }

    @Test
    void TPKT_길이_정합성이_깨지면_그_지점부터_미해독이다() {
        // param-len 을 부풀린 프레임. 남은 전부가 미해독이고 재동기화하지 않는다.
        byte[] frame = S7Fixtures.job(S7Fixtures.readVar(sym(0, 0x52, 16)));
        frame[13] = (byte) (frame[13] + 1);      // S7 헤더 param-len 의 상위 바이트(+256)
        byte[] stream = S7Fixtures.concat(frame, S7Fixtures.job(S7Fixtures.setupCommunication()));

        S7FramingResult r = S7Framer.frames(stream);

        assertTrue(r.frames().isEmpty());
        assertEquals(stream.length, r.undecodedBytes(), "뒤의 유효 프레임도 재동기화로 건지지 않는다");
    }

    @Test
    void 마지막_프레임이_잘려도_예외가_아니라_미해독_바이트다() {
        // 캡처가 프레임 중간에서 끝나는 것은 정상적인 상황이다(1차 프레이머와 같은 판단).
        byte[] whole = S7Fixtures.job(S7Fixtures.readVar(sym(0, 0x52, 16)));
        byte[] stream = S7Fixtures.concat(whole, Arrays.copyOf(whole, whole.length - 3));

        S7FramingResult r = S7Framer.frames(stream);

        assertEquals(1, r.frames().size());
        assertEquals(whole.length - 3, r.undecodedBytes());
    }

    @Test
    void COTP_분할이면_거기서_멈추고_분할을_표시한다() {
        S7FramingResult r = S7Framer.frames(S7Fixtures.concat(
            S7Fixtures.job(S7Fixtures.readVar(sym(0, 0x52, 16))),
            S7Fixtures.fragmented(S7Fixtures.readVar(sym(0, 0x52, 17)))));

        assertEquals(1, r.frames().size());
        assertTrue(r.fragmented());
        assertTrue(r.undecodedBytes() > 0);
    }

    @Test
    void 스트림_중간부터_시작해도_재동기화하지_않는다() {
        // 앞에 이전 프레임의 꼬리 4바이트. TPKT 매직이 어긋나므로 프레임 0개다.
        byte[] stream = S7Fixtures.concat(new byte[]{0x00, 0x02, 0x00, 0x01},
            S7Fixtures.job(S7Fixtures.readVar(sym(0, 0x52, 16))));

        S7FramingResult r = S7Framer.frames(stream);

        assertTrue(r.frames().isEmpty());
        assertEquals(stream.length, r.undecodedBytes());
    }

    @Test
    void TPKT가_아닌_바이트는_프레임이_아니다() {
        S7FramingResult r = S7Framer.frames(
            "SSH-2.0-OpenSSH_9.0\r\n".getBytes(StandardCharsets.US_ASCII));

        assertTrue(r.frames().isEmpty());
    }

    @Test
    void Userdata도_프레임으로_센다() {
        // 관찰은 만들지 않지만(설계 §5) 그 스트림이 S7 이라는 증거는 된다 — 대상 외가 아니다.
        S7FramingResult r = S7Framer.frames(S7Fixtures.userdata(new byte[]{0x00, 0x01, 0x12, 0x04}));

        assertEquals(1, r.frames().size());
        assertEquals(7, r.frames().get(0).rosctr());
    }
}
