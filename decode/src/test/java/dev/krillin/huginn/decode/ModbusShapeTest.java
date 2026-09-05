package dev.krillin.huginn.decode;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

// 함수코드를 짝으로 파라미터화한다. 표는 4≡3, 2≡1, 15≡16 을 주장하는데
// 한쪽만 테스트하면 case 3·case 16·case 1 만 하드코딩한 구현이 전부 통과한다.
class ModbusShapeTest {

    @ParameterizedTest
    @ValueSource(ints = {3, 4})
    void 레지스터_읽기_요청은_정확히_4바이트다(int fc) {
        assertEquals(ModbusShape.REQUEST_ONLY, ModbusShape.of(fc, ModbusFixtures.pdu(0, 2)));
    }

    @ParameterizedTest
    @ValueSource(ints = {3, 4})
    void 레지스터_읽기_응답은_바이트수가_짝수라_요청과_겹치지_않는다(int fc) {
        // 4바이트 응답이려면 바이트수가 3이어야 하는데 레지스터 응답의 바이트수는 항상 2N 이다.
        assertEquals(ModbusShape.RESPONSE_ONLY, ModbusShape.of(fc, new byte[]{4, 0, 1, 0, 2}));
    }

    @ParameterizedTest
    @ValueSource(ints = {15, 16})
    void 다중_쓰기_응답은_정확히_4바이트다(int fc) {
        // 주소2 + 수량2, 가변 필드 없음.
        assertEquals(ModbusShape.RESPONSE_ONLY, ModbusShape.of(fc, new byte[]{0, 0, 0, 2}));
    }

    @Test
    void FC16_요청은_4바이트가_아니다() {
        assertEquals(ModbusShape.REQUEST_ONLY,
            ModbusShape.of(16, new byte[]{0, 0, 0, 2, 4, 0, 1, 0, 2}));
    }

    @Test
    void FC15_최소_요청은_6바이트다() {
        // >= 6 이라는 하한을 밟는 유일한 프레임이다 — 코일 1개 쓰기(바이트수 1).
        // FC 16 만으로는 최소가 7 이라 이 경계를 한 번도 시험하지 않는다.
        assertEquals(ModbusShape.REQUEST_ONLY,
            ModbusShape.of(15, new byte[]{0, 0, 0, 1, 1, (byte) 0xFF}));
    }

    @Test
    void 바이트수가_0x80_이상이어도_부호확장하지_않는다() {
        // pdu[0]·pdu[4] 를 & 0xFF 없이 쓰면 여기서 조용히 UNKNOWN 이 된다.
        // 레지스터 125개 읽기 응답: 바이트수 250. 레지스터 123개 쓰기 요청: 바이트수 246.
        // 후자가 이 태스크의 존재 이유인 FC 16 경로다.
        assertEquals(ModbusShape.RESPONSE_ONLY,
            ModbusShape.of(3, ModbusFixtures.concat(new byte[]{(byte) 250}, new byte[250])));
        assertEquals(ModbusShape.REQUEST_ONLY,
            ModbusShape.of(16, ModbusFixtures.concat(new byte[]{0, 0, 0, 123, (byte) 246}, new byte[246])));
    }

    @Test
    void 바이트수와_실제_길이가_어긋나면_모른다() {
        // 바이트수는 4 라는데 데이터는 2바이트. 길이 7 != 5+4.
        // `pdu.length >= 6 이면 REQUEST_ONLY` 로 축약한 구현을 걸러낸다.
        assertEquals(ModbusShape.UNKNOWN, ModbusShape.of(16, new byte[]{0, 0, 0, 2, 4, 0, 1}));
    }

    @Test
    void 예외_응답은_요청일_수_없다() {
        // §4.1 — 128~255 는 예외 응답 전용이다. 이 행이 없으면 예외 응답만 실린
        // 서버 방향이 형태를 내지 못해 방향 판정이 통째로 침묵한다.
        assertEquals(ModbusShape.RESPONSE_ONLY, ModbusShape.of(0x83, new byte[]{0x02}));
    }

    @Test
    void FC1_응답의_바이트수가_3이면_요청과_구별할_수_없다() {
        // 코일 응답의 바이트수는 홀수도 가능하다(17~24개 코일 → 3바이트).
        // 그때 응답 PDU 도 4바이트라 요청과 겹친다 — 단정하지 않는다.
        assertEquals(ModbusShape.UNKNOWN, ModbusShape.of(1, new byte[]{3, 0x0F, 0x0F, 0x0F}));
    }

    @ParameterizedTest
    @ValueSource(ints = {5, 6, 22})
    void 에코_함수코드는_형태를_모른다(int fc) {
        // 응답이 요청의 에코다(§6.5·§6.6·§6.16). 원리적으로 구별할 수 없다.
        assertEquals(ModbusShape.UNKNOWN, ModbusShape.of(fc, new byte[]{0, 0, 0, 1, 0, 2}));
    }

    @Test
    void 매핑에_없는_함수코드는_형태를_모른다() {
        assertEquals(ModbusShape.UNKNOWN, ModbusShape.of(43, new byte[]{14, 1, 0}));
    }

    @Test
    void 짧은_PDU에도_예외가_아니라_UNKNOWN이다() {
        // pdu[4] 를 보기 전에 길이를 먼저 확인해야 한다.
        assertEquals(ModbusShape.UNKNOWN, ModbusShape.of(16, new byte[]{0, 0}));
        assertEquals(ModbusShape.UNKNOWN, ModbusShape.of(3, new byte[0]));
    }

    @Test
    void 스트림에_두_형태가_섞이면_방향을_모른다() {
        // 재조립이 어긋났거나 캡처가 섞였다. 다수결로 밀어붙이지 않는다.
        assertEquals(ModbusShape.UNKNOWN, ModbusShape.ofStream(List.of(
            new ModbusFrame(1, 1, 3, ModbusFixtures.pdu(0, 2)),          // REQUEST_ONLY
            new ModbusFrame(2, 1, 3, new byte[]{4, 0, 1, 0, 2}))));      // RESPONSE_ONLY
    }

    @Test
    void 형태를_아는_프레임이_하나도_없으면_모른다() {
        assertEquals(ModbusShape.UNKNOWN, ModbusShape.ofStream(List.of(
            new ModbusFrame(1, 1, 6, ModbusFixtures.pdu(0, 1)))));
    }

    @Test
    void 빈_목록도_모른다() {
        // 캡처에 없는 방향은 프레임 0개다. Task 13 의 단방향 캡처 판정이 전부 이 값에 기댄다.
        assertEquals(ModbusShape.UNKNOWN, ModbusShape.ofStream(List.of()));
    }

    @Test
    void 아는_프레임이_하나라도_있고_충돌이_없으면_그_형태다() {
        assertEquals(ModbusShape.REQUEST_ONLY, ModbusShape.ofStream(List.of(
            new ModbusFrame(1, 1, 6, ModbusFixtures.pdu(0, 1)),          // UNKNOWN
            new ModbusFrame(2, 1, 16, new byte[]{0, 0, 0, 2, 4, 0, 1, 0, 2}))));
    }
}
