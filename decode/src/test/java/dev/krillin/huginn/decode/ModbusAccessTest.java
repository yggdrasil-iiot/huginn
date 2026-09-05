package dev.krillin.huginn.decode;

import dev.krillin.huginn.reconcile.Access;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.assertEquals;

class ModbusAccessTest {

    /** 함수코드만으로 판정이 끝나는 코드들 — PDU 를 보지 않는다. */
    private static final byte[] NO_PDU = new byte[0];

    @ParameterizedTest
    @ValueSource(ints = {1, 2, 3, 4, 7, 11, 12, 17, 20, 24})
    void 읽기_함수코드(int fc) {
        assertEquals(Access.READ, ModbusAccess.of(fc, NO_PDU));
    }

    @ParameterizedTest
    @ValueSource(ints = {5, 6, 15, 16, 21, 22, 23})
    void 쓰기_함수코드(int fc) {
        // 21(Write File Record)이 빠지면 미등록 장비의 파일 레코드 쓰기가 보고되지 않는다.
        assertEquals(Access.WRITE, ModbusAccess.of(fc, NO_PDU));
    }

    @Test
    void 진단은_제어로_본다() {
        // 서브함수에 Restart Communications / Force Listen Only 가 있어 보수적으로 분류한다.
        // 대부분의 서브함수는 카운터 읽기이므로 과대분류인 면이 있다.
        assertEquals(Access.CONTROL, ModbusAccess.of(8, NO_PDU));
    }

    @Test
    void 장치식별_조회는_읽기다() {
        // MEI 14 = Read Device Identification. 실캡처의 FC 43 요청 35 건이 전부 이것이다.
        // 1차는 MEI 를 안 봐서 UNDECIDABLE 로 뒀고, 그래서 151021 의 장비 열거 스캔이
        // Finding 이 되지 않았다(1차 §10).
        assertEquals(Access.READ, ModbusAccess.of(43, new byte[]{0x0E, 0x01, 0x00}));
    }

    @Test
    void CANopen_전송은_여전히_UNDECIDABLE이다() {
        // MEI 13 은 읽기·쓰기를 모두 실어 나른다. 더 파고들지 않는 한 단정할 수 없다 —
        // 1차의 판단은 폐기가 아니라 적용 범위가 여기로 좁아진 것이다.
        assertEquals(Access.UNDECIDABLE, ModbusAccess.of(43, new byte[]{0x0D, 0x01}));
    }

    @Test
    void 모르는_MEI_타입도_UNDECIDABLE이다() {
        assertEquals(Access.UNDECIDABLE, ModbusAccess.of(43, new byte[]{0x7F, 0x01}));
    }

    @Test
    void MEI를_읽을_수_없으면_UNDECIDABLE이다() {
        // PDU 가 비었거나 잘렸다. 지어내지 않는다.
        assertEquals(Access.UNDECIDABLE, ModbusAccess.of(43, new byte[0]));
    }

    @ParameterizedTest
    @ValueSource(ints = {0, 9, 13, 99, 0x83})
    void 정의되지_않은_함수코드는_UNDECIDABLE이다(int fc) {
        // 0x83 은 FC 3 의 예외 응답이다. 설계 §5-⑤ 로 응답은 관찰하지 않지만,
        // 단방향 캡처에서 새어 들어와도 위반으로 단정하지 않도록 여기서 고정한다.
        assertEquals(Access.UNDECIDABLE, ModbusAccess.of(fc, NO_PDU));
    }
}
