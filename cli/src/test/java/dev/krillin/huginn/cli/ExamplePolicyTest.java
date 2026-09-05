package dev.krillin.huginn.cli;

import dev.krillin.huginn.contract.CommunicationPolicy;
import dev.krillin.huginn.contract.PolicyLoader;
import dev.krillin.huginn.reconcile.Access;
import dev.krillin.huginn.reconcile.Protocol;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 저장소의 {@code examples/policy.yaml} 을 실제로 읽는다 — 예시가 썩는 것을 막는 유일한 장치다.
 * README 가 가리키는 파일이 로딩조차 안 되면 처음 쓰는 사람이 거기서 막힌다.
 */
class ExamplePolicyTest {

    @Test
    void 저장소의_예시_정책은_로딩되고_선언한_대로_판정한다() throws IOException {
        CommunicationPolicy policy = PolicyLoader.parse(
            Files.readString(examplePolicy(), StandardCharsets.UTF_8));

        assertTrue(policy.allows("10.0.1.20", "10.0.2.11", Protocol.MODBUS_TCP, Access.WRITE),
            "hmi-01 → plc-mixer 는 쓰기가 선언돼 있다");
        assertTrue(policy.allows("10.0.1.50", "10.0.2.11", Protocol.MODBUS_TCP, Access.READ));
        assertFalse(policy.allows("10.0.1.50", "10.0.2.11", Protocol.MODBUS_TCP, Access.WRITE),
            "히스토리안의 쓰기는 선언돼 있지 않다 — 주석이 아니라 판정으로 고정한다");
    }

    /** surefire 의 작업 디렉터리는 모듈 basedir(cli/)이지만, 모듈 단독 실행도 견디게 둔다. */
    private static Path examplePolicy() {
        Path fromModule = Path.of("..", "examples", "policy.yaml");
        return Files.exists(fromModule) ? fromModule : Path.of("examples", "policy.yaml");
    }
}
