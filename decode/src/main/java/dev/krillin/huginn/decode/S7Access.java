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
 * <p><b>A단계에서는 제어 계열이 아직 UNDECIDABLE 이다.</b> {@code 0x28} PLC Control ·
 * {@code 0x29} PLC Stop · {@code 0x1A}~{@code 0x1F} 블록 다운로드/업로드는 B단계에서
 * CONTROL 로 올린다. 검증 없이 미리 올리면 확인되지 않은 판정이 리포트에 나간다.
 */
public final class S7Access {

    private static final Map<Integer, Access> BY_FUNCTION_CODE = Map.of(
        0x04, Access.READ,     // Read Var
        0x05, Access.WRITE);   // Write Var

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
