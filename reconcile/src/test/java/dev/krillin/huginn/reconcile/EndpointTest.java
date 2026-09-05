package dev.krillin.huginn.reconcile;

import static org.junit.jupiter.api.Assertions.assertEquals;
import org.junit.jupiter.api.Test;

class EndpointTest {
    @Test
    void 주소와_포트를_사람이_읽는_형태로_표기한다() {
        assertEquals("10.0.1.20:502", new Endpoint("10.0.1.20", 502).toString());
    }
}
