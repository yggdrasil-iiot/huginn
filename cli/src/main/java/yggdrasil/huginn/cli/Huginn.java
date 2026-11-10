package yggdrasil.huginn.cli;

import yggdrasil.huginn.contract.PolicyException;
import yggdrasil.huginn.pcap.PcapException;
import yggdrasil.huginn.zeek.ZeekLogException;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

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

    private static final String USAGE = """
        사용법: huginn <capture.pcap> <policy.yaml>
               huginn --zeek-log <file> [--zeek-log <file> ...] <policy.yaml>
        """;

    private static final String ZEEK_LOG = "--zeek-log";

    public static int run(String[] args) {
        try {
            Rendered report;
            if (args.length >= 1 && args[0].equals(ZEEK_LOG)) {
                report = zeek(args);
            } else if (args.length == 2) {
                byte[] pcap = Files.readAllBytes(Path.of(args[0]));
                String policyYaml = Files.readString(Path.of(args[1]), StandardCharsets.UTF_8);
                report = Pipeline.run(pcap, policyYaml);
            } else {
                System.err.print(USAGE);
                return 2;
            }
            if (report == null) {
                return 2;
            }
            System.out.print(report.render());
            return report.findings().isEmpty() ? 0 : 1;
        } catch (IOException | InvalidPathException | PcapException | PolicyException | ZeekLogException e) {
            System.err.println("오류: " + e.getMessage());
            return 2;
        }
    }

    /**
     * {@code --zeek-log <file>} 쌍이 하나 이상, 마지막이 정책이다. 디렉터리는 받지 않는다 —
     * 로테이션된 사본이나 겹치는 내보내기가 섞여 같은 요청을 두 번 세지 않도록, 무엇을 읽을지는
     * 사용자가 정한다. 같은 파일을 두 번 주면 거부한다.
     *
     * @return 사용법 오류면 null
     */
    private static Rendered zeek(String[] args) throws IOException {
        if (args.length < 3 || args.length % 2 == 0) {
            System.err.print(USAGE);
            return null;
        }
        Map<String, String> logs = new LinkedHashMap<>();
        Set<Path> seen = new HashSet<>();
        for (int i = 0; i < args.length - 1; i += 2) {
            if (!args[i].equals(ZEEK_LOG)) {
                System.err.print(USAGE);
                return null;
            }
            Path file = Path.of(args[i + 1]);
            if (!seen.add(file.toRealPath())) {
                throw new ZeekLogException("같은 로그를 두 번 줬다: " + args[i + 1]);
            }
            logs.put(args[i + 1], Files.readString(file, StandardCharsets.UTF_8));
        }
        String policyYaml = Files.readString(Path.of(args[args.length - 1]), StandardCharsets.UTF_8);
        return Pipeline.runZeek(logs, policyYaml);
    }
}
