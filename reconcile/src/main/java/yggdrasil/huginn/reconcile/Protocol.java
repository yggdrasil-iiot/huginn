package yggdrasil.huginn.reconcile;

/**
 * 해독한 산업 프로토콜.
 *
 * 이 열거형이 reconcile 에 있는 것은 정책 계약이 프로토콜을 이름으로 선언하기 때문이다.
 * decode 경계가 막는 것은 프로토콜 "이름" 이 아니라 프레이밍·함수코드 지식이다.
 *
 * <p>{@code S7COMM_PLUS} 는 {@code S7COMM} 과 <b>다른 이름</b>이다. 하나로 접으면 S7-300 에
 * 선언한 {@code S7COMM: [READ]} 가 S7-1500 으로 가는 S7comm-plus 읽기까지 조용히 허용한다.
 * 이 프로토콜은 Zeek ICSNPP 로그로만 관찰한다 — Huginn 의 해독기는 S7comm-plus 를 읽지 않는다.
 */
public enum Protocol { MODBUS_TCP, S7COMM, S7COMM_PLUS }
