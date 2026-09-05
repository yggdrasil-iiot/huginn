package dev.krillin.huginn.cli;

import dev.krillin.huginn.contract.PolicyException;
import dev.krillin.huginn.pcap.PcapException;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;

/**
 * 진입점.
 *
 * <p>세 층으로 나눈 이유는 하나다 — {@code main} 이 {@code System.exit} 을 부르면 테스트에서
 * JVM 이 죽는다. 테스트는 {@link #run(String[])} 을 부른다.
 *
 * <p><b>종료 코드</b> — 0: 위반 없음 · 1: 위반 있음 · 2: 사용법·입력·계약 오류.
 * <b>UNDECIDABLE 이 아무리 많아도 위반이 0이면 0을 낸다</b> — 커버리지는 리포트가 항상 내므로
 * 종료 코드까지 흐리지 않는다.
 */
public final class Huginn {

    private Huginn() {
    }

    public static void main(String[] args) {
        System.exit(run(args));
    }

    public static int run(String[] args) {
        if (args.length != 2) {
            System.err.println("사용법: huginn <capture.pcap> <policy.yaml>");
            return 2;
        }
        try {
            byte[] pcap = Files.readAllBytes(Path.of(args[0]));
            String policyYaml = Files.readString(Path.of(args[1]), StandardCharsets.UTF_8);
            Report report = Pipeline.run(pcap, policyYaml);
            System.out.print(report.render());
            return report.findings().isEmpty() ? 0 : 1;
        } catch (IOException | InvalidPathException | PcapException | PolicyException e) {
            System.err.println("오류: " + e.getMessage());
            return 2;
        }
    }
}
