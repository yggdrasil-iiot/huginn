package dev.krillin.huginn.contract;

/** 계약 오류. 조회 실패가 아니라 정책 자체가 잘못되었을 때 던진다 — 즉시, 시끄럽게. */
public class PolicyException extends RuntimeException {

    public PolicyException(String message) {
        super(message);
    }

    public PolicyException(String message, Throwable cause) {
        super(message, cause);
    }
}
