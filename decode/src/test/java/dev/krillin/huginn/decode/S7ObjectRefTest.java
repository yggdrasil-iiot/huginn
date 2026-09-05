package dev.krillin.huginn.decode;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class S7ObjectRefTest {

    @Test
    void 실캡처의_1200SYM_주소를_표기한다() {
        // 설계 §4 의 실제 바이트: area1 0x0000 · area2 0x0052(Flags M) · LID 16
        assertEquals("sym:m/16",
            S7ObjectRef.of(S7Fixtures.readVar(S7Fixtures.sym(0x0000, 0x0052, 16))));
    }

    @Test
    void LID가_여럿이면_슬래시로_잇는다() {
        assertEquals("sym:m/16/3",
            S7ObjectRef.of(S7Fixtures.readVar(S7Fixtures.sym(0, 0x52, 16, 3))));
    }

    @Test
    void area1이_0이_아니면_이름을_지어내지_않는다() {
        // area1 != 0 이면 area2 는 영역 코드가 아니라 DB 번호 계열이다. 실캡처에 0건이라 미검증 경로다.
        assertEquals("sym:0x0001:0x0052/16",
            S7ObjectRef.of(S7Fixtures.readVar(S7Fixtures.sym(1, 0x52, 16))));
    }

    @Test
    void 아는_area2는_0x0052_하나뿐이다() {
        assertEquals("sym:0x0000:0x0084/16",
            S7ObjectRef.of(S7Fixtures.readVar(S7Fixtures.sym(0, 0x84, 16))));
    }

    @Test
    void S7ANY_DB_주소를_표기한다() {
        assertEquals("db1.dbx20.0",
            S7ObjectRef.of(S7Fixtures.readVar(S7Fixtures.s7any(0x84, 1, 20, 0))));
    }

    @Test
    void S7ANY_플래그_주소를_표기한다() {
        assertEquals("m20.3",
            S7ObjectRef.of(S7Fixtures.readVar(S7Fixtures.s7any(0x83, 0, 20, 3))));
    }

    @Test
    void 입력과_출력도_표기한다() {
        assertEquals("i0.0", S7ObjectRef.of(S7Fixtures.readVar(S7Fixtures.s7any(0x81, 0, 0, 0))));
        assertEquals("q4.1", S7ObjectRef.of(S7Fixtures.readVar(S7Fixtures.s7any(0x82, 0, 4, 1))));
    }

    @Test
    void 카운터와_타이머는_비트_주소가_없다() {
        assertEquals("c3", S7ObjectRef.of(S7Fixtures.readVar(S7Fixtures.s7any(0x1C, 0, 3, 0))));
        assertEquals("t7", S7ObjectRef.of(S7Fixtures.readVar(S7Fixtures.s7any(0x1D, 0, 7, 0))));
    }

    @Test
    void 항목이_여럿이면_첫_항목과_개수를_적는다() {
        String ref = S7ObjectRef.of(S7Fixtures.readVar(
            S7Fixtures.sym(0, 0x52, 16), S7Fixtures.sym(0, 0x52, 17), S7Fixtures.sym(0, 0x52, 18)));

        assertEquals("sym:m/16 (+2)", ref);
    }

    @Test
    void 첫_항목을_못_읽어도_항목_수는_적는다() {
        // 항목이 여럿이라는 사실은 첫 항목을 읽었는지와 무관하다.
        byte[] parameter = S7Fixtures.concat(new byte[]{0x04, 0x02, 0x12, 0x02, 0x77, 0x00},
                                             S7Fixtures.sym(0, 0x52, 16));

        assertEquals("fc:4 (+1)", S7ObjectRef.of(parameter));
    }

    @Test
    void 항목이_없는_함수는_함수코드만_적는다() {
        // 0xF0 을 부호 있는 byte 로 쓰면 -16 이 나온다.
        assertEquals("fc:240", S7ObjectRef.of(S7Fixtures.setupCommunication()));
    }

    @Test
    void 제어_함수는_이름으로_적는다() {
        // fc:41 로는 운영자가 무엇이 일어났는지 모른다. 파싱이 아니라 정적 이름표라 틀릴 여지가 없다.
        assertEquals("plc-stop", S7ObjectRef.of(new byte[]{0x29, 0x00}));
        assertEquals("plc-control", S7ObjectRef.of(new byte[]{0x28, 0x00}));
        assertEquals("download-request", S7ObjectRef.of(new byte[]{0x1A, 0x00}));
        assertEquals("upload-end", S7ObjectRef.of(new byte[]{0x1F, 0x00}));
    }

    @Test
    void 제어_함수의_이름은_대상까지_말하지_않는다() {
        // 어떤 블록을 내려받는지는 가변길이 식별자에 있고 우리는 읽지 않는다.
        // 이름이 대상을 아는 척하면 근거가 아니라 추측이 된다.
        assertEquals("download-block", S7ObjectRef.of(new byte[]{0x1B, 0x00, 0x01, 0x02, 0x03}));
    }

    @Test
    void 파라미터가_짧으면_지어내지_않는다() {
        assertEquals("fc:4", S7ObjectRef.of(new byte[]{0x04, 0x01, 0x12}));
    }
}
