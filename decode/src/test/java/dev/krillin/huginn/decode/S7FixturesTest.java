package dev.krillin.huginn.decode;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class S7FixturesTest {

    @Test
    void 설계_문서의_실제_캡처_바이트를_재현한다() {
        // 4SICS 151020 에서 뜬 Write Var 요청 한 건(설계 §4).
        // 픽스처가 실물과 다르면 이 계획의 모든 테스트가 허구를 검증하게 된다.
        byte[] frame = S7Fixtures.job(S7Fixtures.writeVar(S7Fixtures.sym(0x0000, 0x0052, 16)));

        assertEquals(0x03, frame[0] & 0xFF);
        assertEquals(0x00, frame[1] & 0xFF);
        assertEquals(4 + 3 + 10 + 18, ((frame[2] & 0xFF) << 8) | (frame[3] & 0xFF),
            "TPKT 길이 = 4 + COTP 3 + S7 헤더 10 + 파라미터 18");
        assertEquals(0x32, frame[7] & 0xFF, "S7 프로토콜 id");
        assertEquals(0x01, frame[8] & 0xFF, "ROSCTR Job");
        assertEquals(0x05, frame[17] & 0xFF, "파라미터 첫 바이트 = 함수코드 Write Var");
        assertEquals(0xB2, frame[21] & 0xFF, "syntax id 1200SYM");
    }
}
