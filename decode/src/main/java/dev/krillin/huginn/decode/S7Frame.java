package dev.krillin.huginn.decode;

/**
 * S7comm 프레임 하나.
 *
 * @param rosctr    1 Job(요청) · 2 Ack · 3 Ack_Data(응답) · 7 Userdata
 * @param parameter 파라미터 바이트 전체. ROSCTR 1 이면 첫 바이트가 함수코드다
 */
public record S7Frame(int rosctr, byte[] parameter) {

    /** 파라미터가 비었으면 -1. ROSCTR 7 의 파라미터는 함수코드로 해석하지 않는다(설계 §5). */
    public int functionCode() {
        return parameter.length > 0 ? parameter[0] & 0xFF : -1;
    }
}
