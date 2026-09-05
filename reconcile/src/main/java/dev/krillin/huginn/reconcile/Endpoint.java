package dev.krillin.huginn.reconcile;

/** 통신 한쪽 끝. 주소는 문자열로 둔다 — 판정에 산술이 필요 없고, 표기가 그대로 근거가 된다. */
public record Endpoint(String address, int port) {
    @Override public String toString() { return address + ":" + port; }
}
