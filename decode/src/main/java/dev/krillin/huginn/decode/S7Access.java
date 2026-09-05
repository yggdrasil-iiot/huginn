package dev.krillin.huginn.decode;

import dev.krillin.huginn.reconcile.Access;

import java.util.Map;

/**
 * S7comm 함수코드를 {@link Access} 로 옮긴다.
 *
 * <p>{@link ModbusAccess} 와 같은 형태를 쓴다 — 1차 설계가 "2차의 S7comm 도 같은 형태를
 * 재사용한다"고 적어둔 그것이다. <b>이 목록 자체가 문서</b>이며, 표에 없는 함수코드는 전부
 * {@link Access#UNDECIDABLE} 이다.
 *
 * <p><b>제어 계열은 서브서비스를 보지 않고 통째로 CONTROL 이다.</b> {@code 0x28} 의 실제 동작은
 * 가변길이 서비스 문자열({@code P_PROGRAM}·{@code _INSE})에 있고 블록 함수의 대상 블록은
 * 파일명 형태의 식별자에 있는데, 둘 다 읽지 않는다 — 실캡처가 없어 대조할 수 없기 때문이다.
 * 1차가 Modbus FC 8(Diagnostics)을 서브함수 없이 올린 것과 같은 보수적 판단이며,
 * <b>같은 이유로 과대분류인 면이 있다.</b>
 */
public final class S7Access {

    private static final Map<Integer, Access> BY_FUNCTION_CODE = Map.ofEntries(
        Map.entry(0x04, Access.READ),      // Read Var
        Map.entry(0x05, Access.WRITE),     // Write Var

        // PLC 정지는 눈에 띄지만, 로직을 조용히 바꾸고 가는 블록 다운로드가 실제 위험이다.
        Map.entry(0x28, Access.CONTROL),   // PLC Control
        Map.entry(0x29, Access.CONTROL),   // PLC Stop
        Map.entry(0x1A, Access.CONTROL),   // Request download
        Map.entry(0x1B, Access.CONTROL),   // Download block
        Map.entry(0x1C, Access.CONTROL),   // Download ended
        Map.entry(0x1D, Access.CONTROL),   // Start upload
        Map.entry(0x1E, Access.CONTROL),   // Upload
        Map.entry(0x1F, Access.CONTROL));  // End upload

    private S7Access() {
    }

    /**
     * @param functionCode {@link S7Frame#functionCode()} 의 값. 파라미터가 비면 -1 이 오고,
     *                     그것도 UNDECIDABLE 이다 — 모르는 것을 아는 척하지 않는다
     */
    public static Access of(int functionCode) {
        return BY_FUNCTION_CODE.getOrDefault(functionCode, Access.UNDECIDABLE);
    }
}
