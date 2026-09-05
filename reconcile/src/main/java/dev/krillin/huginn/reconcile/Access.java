package dev.krillin.huginn.reconcile;

/**
 * 접근 유형.
 *
 * UNDECIDABLE 이 값 하나로 존재하는 것이 요점이다 — 해독 못 한 것을 READ 로 치면 우회를 놓친다.
 */
public enum Access { READ, WRITE, CONTROL, UNDECIDABLE }
