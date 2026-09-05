package dev.krillin.huginn.reconcile;

import java.util.ArrayList;
import java.util.List;

/**
 * 정책에 대해 Observation 목록을 대사한다. 순수 로직 — 입출력도, 프로토콜 지식도 없다.
 *
 * 정책이 명시적으로 허용하지 않은 것은 전부 위반이다(deny-by-default). UNDECIDABLE 은
 * 위반으로도 정상으로도 단정하지 않고 별도로 센다.
 */
public final class Reconciler {

    private final PolicyView policy;

    public Reconciler(PolicyView policy) {
        this.policy = policy;
    }

    public ReconcileResult reconcile(List<Observation> observations) {
        List<Finding> findings = new ArrayList<>();
        int undecidableCount = 0;

        for (Observation o : observations) {
            if (o.access() == Access.UNDECIDABLE) {
                undecidableCount++;
                continue;
            }

            boolean allowed = policy.allows(
                o.source().address(), o.target().address(), o.protocol(), o.access());

            if (!allowed) {
                Severity severity = switch (o.access()) {
                    case WRITE, CONTROL -> Severity.HIGH;
                    case READ -> Severity.MEDIUM;
                    case UNDECIDABLE -> throw new IllegalStateException("unreachable");
                };
                String detail = "선언되지 않은 통신: " + o.source() + " → " + o.target()
                    + " " + o.protocol() + " " + o.access();
                findings.add(new Finding(severity, Finding.Kind.UNDECLARED, o, detail));
            }
        }

        return new ReconcileResult(findings, observations.size(), undecidableCount);
    }
}
