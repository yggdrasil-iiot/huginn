package dev.krillin.huginn.decode;

/**
 * 수용 정책이 프로토콜을 몰라도 되게 하는 최소 계약.
 *
 * <p>딱 두 메서드다. 프로토콜 고유의 것(프레임 목록·COTP 분할 여부)은 호출자가 구체 타입에서
 * 그대로 꺼내 쓴다 — 여기로 끌어올리면 이음매가 프로토콜을 알게 된다.
 */
interface Framing {

    int frameCount();

    int leftoverBytes();
}
