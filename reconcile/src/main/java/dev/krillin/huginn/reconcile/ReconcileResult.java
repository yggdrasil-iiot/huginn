package dev.krillin.huginn.reconcile;

import java.util.List;

/** observedCount 는 입력 Observation 총수이며 UNDECIDABLE 을 포함한다. */
public record ReconcileResult(List<Finding> findings, int observedCount, int undecidableCount) {}
