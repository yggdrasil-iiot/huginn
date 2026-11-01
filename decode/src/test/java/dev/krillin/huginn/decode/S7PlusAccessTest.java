package dev.krillin.huginn.decode;

import dev.krillin.huginn.reconcile.Access;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.assertEquals;

class S7PlusAccessTest {

    @ParameterizedTest
    @ValueSource(ints = {0x054C, 0x0586, 0x04BB})
    void 변수_읽기와_객체_열람은_READ다(int fc) {
        // Get Multi Variables · Get Variable Sub Streamed · Explore
        assertEquals(Access.READ, S7PlusAccess.of(fc));
    }

    @ParameterizedTest
    @ValueSource(ints = {0x04F2, 0x0542})
    void 변수_쓰기는_WRITE다(int fc) {
        // Set Variable · Set Multi Variables. CPU 운전·정지도 Set Variable 로 실리므로 바닥이다.
        assertEquals(Access.WRITE, S7PlusAccess.of(fc));
    }

    @ParameterizedTest
    @ValueSource(ints = {0x04CA, 0x04D4, 0x0556, 0x0560, 0x056B, 0x0524})
    void 일상과_제어가_같은_코드를_쓰는_것은_UNDECIDABLE이다(int fc) {
        // Create Object 는 모든 세션의 첫 메시지다. CONTROL 로 올리면 정상 세션이 전부 HIGH 가 된다.
        assertEquals(Access.UNDECIDABLE, S7PlusAccess.of(fc));
    }

    @ParameterizedTest
    @ValueSource(ints = {0x0000, 0x9999, -1})
    void 모르는_함수코드는_UNDECIDABLE이다(int fc) {
        assertEquals(Access.UNDECIDABLE, S7PlusAccess.of(fc));
    }
}
