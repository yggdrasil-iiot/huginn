package dev.krillin.huginn.reconcile;

/** 대사기가 정책에 대해 아는 전부. contract 모듈이 이것을 구현한다 — 의존 방향은 contract → reconcile 이다. */
@FunctionalInterface
public interface PolicyView {
    boolean allows(String sourceAddress, String targetAddress, Protocol protocol, Access access);
}
