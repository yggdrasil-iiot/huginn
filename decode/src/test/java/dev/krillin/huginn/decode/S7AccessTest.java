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
    @ValueSource(ints = {0x28, 0x29, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F})
    void A단계에서_제어_계열은_아직_UNDECIDABLE이다(int fc) {
        // B단계에서 CONTROL 로 올린다. 여기서 미리 올리면 검증되지 않은 판정이 리포트에 나간다.
        assertEquals(Access.UNDECIDABLE, S7Access.of(fc));
    }

    @ParameterizedTest
    @ValueSource(ints = {0x00, 0x03, 0x99, -1})
    void 모르는_함수코드는_UNDECIDABLE이다(int fc) {
        // -1 은 파라미터가 비어 함수코드를 못 읽은 프레임이다(S7Frame.functionCode 계약).
        assertEquals(Access.UNDECIDABLE, S7Access.of(fc));
    }
}
