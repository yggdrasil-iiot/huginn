package dev.krillin.huginn.decode;

import dev.krillin.huginn.reconcile.Access;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.assertEquals;

class S7AccessTest {

    @Test
    void 읽기는_0x04다() {
        assertEquals(Access.READ, S7Access.of(0x04));
    }

    @Test
    void 쓰기는_0x05다() {
        assertEquals(Access.WRITE, S7Access.of(0x05));
    }

    @Test
    void 세션_설정은_UNDECIDABLE이다() {
        // 0xF0 은 데이터 접근이 아니다. READ 로 치면 세션마다 읽기 관찰이 하나씩 생긴다.
        assertEquals(Access.UNDECIDABLE, S7Access.of(0xF0));
    }

    @ParameterizedTest
    @ValueSource(ints = {0x28, 0x29})
    void PLC_제어는_CONTROL이다(int fc) {
        // 0x28 PLC Control · 0x29 PLC Stop. 서브서비스 문자열은 읽지 않으므로 과대분류인
        // 면이 있다 — 1차가 Modbus FC 8 을 통째로 CONTROL 로 올린 것과 같은 보수적 판단이다.
        assertEquals(Access.CONTROL, S7Access.of(fc));
    }

    @ParameterizedTest
    @ValueSource(ints = {0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F})
    void 블록_다운로드와_업로드는_CONTROL이다(int fc) {
        // 엔지니어링 워크스테이션이 PLC 에 로직을 내려받는 경로 — S7 에서 가장 중요한 우회 신호다.
        // PLC 정지는 눈에 띄지만 로직을 조용히 바꾸고 가는 쪽이 실제 위험이다.
        assertEquals(Access.CONTROL, S7Access.of(fc));
    }

    @ParameterizedTest
    @ValueSource(ints = {0x00, 0x03, 0x99, -1})
    void 모르는_함수코드는_UNDECIDABLE이다(int fc) {
        // -1 은 파라미터가 비어 함수코드를 못 읽은 프레임이다(S7Frame.functionCode 계약).
        assertEquals(Access.UNDECIDABLE, S7Access.of(fc));
    }
}
