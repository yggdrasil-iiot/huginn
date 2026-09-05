package dev.krillin.huginn.decode;

import dev.krillin.huginn.reconcile.Access;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.assertEquals;

class ModbusAccessTest {

    @ParameterizedTest
    @ValueSource(ints = {1, 2, 3, 4, 7, 11, 12, 17, 20, 24})
    void 읽기_함수코드(int fc) {
        assertEquals(Access.READ, ModbusAccess.of(fc));
    }

    @ParameterizedTest
    @ValueSource(ints = {5, 6, 15, 16, 21, 22, 23})
    void 쓰기_함수코드(int fc) {
        // 21(Write File Record)이 빠지면 미등록 장비의 파일 레코드 쓰기가 보고되지 않는다.
        assertEquals(Access.WRITE, ModbusAccess.of(fc));
    }

    @Test
    void 진단은_제어로_본다() {
        // 서브함수에 Restart Communications / Force Listen Only 가 있어 보수적으로 분류한다.
        // 대부분의 서브함수는 카운터 읽기이므로 과대분류인 면이 있다.
        assertEquals(Access.CONTROL, ModbusAccess.of(8));
    }

    @Test
    void 캡슐화_전송은_UNDECIDABLE이다() {
        // 43 의 의미는 MEI Type 이 정한다 — MEI 14 는 Read Device Identification(읽기),
        // MEI 13(CANopen)은 읽기·쓰기를 모두 실어 나른다. MEI 를 보지 않고 CONTROL 로 올리면
        // 정상적인 장치식별 조회가 최고 심각도 위반이 된다.
        assertEquals(Access.UNDECIDABLE, ModbusAccess.of(43));
    }

    @ParameterizedTest
    @ValueSource(ints = {0, 9, 13, 99, 0x83})
    void 정의되지_않은_함수코드는_UNDECIDABLE이다(int fc) {
        // 0x83 은 FC 3 의 예외 응답이다. 설계 §5-⑤ 로 응답은 관찰하지 않지만,
        // 단방향 캡처에서 새어 들어와도 위반으로 단정하지 않도록 여기서 고정한다.
        assertEquals(Access.UNDECIDABLE, ModbusAccess.of(fc));
    }
}
