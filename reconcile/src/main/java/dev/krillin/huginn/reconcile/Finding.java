package dev.krillin.huginn.reconcile;

public record Finding(Severity severity, Kind kind, Observation evidence, String detail) {
    /**
     * 1차는 한 종류다. UNDECLARED_PEER/PROTOCOL/ACCESS 로 나눌 수 있지만, 근거 Observation 이
     * 이미 무엇이 어긋났는지를 담고 있어 세분화의 실익이 아직 없다(설계 §5).
     */
    public enum Kind { UNDECLARED }
}
