package dev.krillin.huginn.decode;

import dev.krillin.huginn.reconcile.Access;

import java.util.Map;

/**
 * S7comm-plus 함수코드를 {@link Access} 로 옮긴다.
 *
 * <p>{@link ModbusAccess}·{@link S7Access} 와 같은 형태다 — <b>이 목록 자체가 문서</b>이며, 표에
 * 없는 함수코드는 전부 {@link Access#UNDECIDABLE} 이다. 코드와 이름은 Zeek ICSNPP
 * {@code consts.zeek}({@code s7comm_plus_functions}, cisagov/icsnpp-s7comm 102a35c)의 열한 개다.
 * Huginn 은 S7comm-plus 프레임을 해독하지 않으므로 이 표를 쓰는 곳은 Zeek 로그 입력뿐이다.
 *
 * <p><b>쓰기는 바닥이지 천장이 아니다.</b> S7-1200/1500 의 운전·정지도 CPU 객체에 대한
 * Set Variable 로 실린다. 로그에 객체 식별자가 없어 둘을 가를 수 없으므로 WRITE 로 둔다 —
 * 이 표가 CONTROL 을 WRITE 로 낮춰 보는 경우가 있다는 뜻이다.
 *
 * <p><b>UNDECIDABLE 여섯은 세션의 일상과 제어가 같은 코드를 쓰는 것들이다.</b> Create Object 는
 * 모든 세션의 첫 메시지이고, Begin/End Sequence 는 다운로드도 감싸지만 평범한 묶음도 감싼다.
 * Delete Object 와 Invoke 는 대상 객체·메서드를, Get Link 는 의미를 로그만으로 정할 수 없다.
 * CONTROL 로 올리면 선언된 쌍의 정상 세션이 전부 HIGH 가 되고, READ 로 내리면 제어를 숨긴다.
 * S7comm 의 Setup Communication({@code 0xf0})이 표에 없는 것과 같은 판단이다.
 */
public final class S7PlusAccess {

    private static final Map<Integer, Access> BY_FUNCTION_CODE = Map.ofEntries(
        Map.entry(0x054C, Access.READ),    // Get Multi Variables
        Map.entry(0x0586, Access.READ),    // Get Variable Sub Streamed
        Map.entry(0x04BB, Access.READ),    // Explore — 객체 트리 열람, 메타데이터 읽기

        Map.entry(0x04F2, Access.WRITE),   // Set Variable
        Map.entry(0x0542, Access.WRITE));  // Set Multi Variables

    // 표에 없어서 UNDECIDABLE 인 것들(의도적):
    // 0x04CA Create Object · 0x04D4 Delete Object · 0x0556 Begin Sequence ·
    // 0x0560 End Sequence · 0x056B Invoke · 0x0524 Get Link

    private S7PlusAccess() {
    }

    /** @param functionCode 로그의 {@code function_code}(예: {@code 0x04f2}). 모르면 -1 을 넘긴다 */
    public static Access of(int functionCode) {
        return BY_FUNCTION_CODE.getOrDefault(functionCode, Access.UNDECIDABLE);
    }
}
