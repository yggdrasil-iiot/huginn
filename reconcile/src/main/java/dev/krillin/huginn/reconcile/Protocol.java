package dev.krillin.huginn.reconcile;

/**
 * 해독한 산업 프로토콜.
 *
 * 이 열거형이 reconcile 에 있는 것은 정책 계약이 프로토콜을 이름으로 선언하기 때문이다.
 * decode 경계가 막는 것은 프로토콜 "이름" 이 아니라 프레이밍·함수코드 지식이다.
 */
public enum Protocol { MODBUS_TCP, S7COMM }
