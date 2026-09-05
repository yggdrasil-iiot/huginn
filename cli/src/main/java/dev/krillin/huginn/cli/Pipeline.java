package dev.krillin.huginn.cli;

import dev.krillin.huginn.contract.CommunicationPolicy;
import dev.krillin.huginn.contract.PolicyLoader;
import dev.krillin.huginn.decode.TrafficObserver;
import dev.krillin.huginn.decode.ObservationResult;
import dev.krillin.huginn.pcap.CapturedPacket;
import dev.krillin.huginn.pcap.DecodedFrames;
import dev.krillin.huginn.pcap.FrameDecoder;
import dev.krillin.huginn.pcap.PcapReader;
import dev.krillin.huginn.pcap.TcpStream;
import dev.krillin.huginn.pcap.TcpStreamAssembler;
import dev.krillin.huginn.reconcile.ReconcileResult;
import dev.krillin.huginn.reconcile.Reconciler;

import java.util.List;

/**
 * pcap 바이트와 정책 YAML 에서 리포트까지 — 순수 실행이다. 파일도 표준출력도 종료 코드도
 * 여기서는 다루지 않는다({@link Huginn} 이 한다).
 *
 * <p>커버리지는 각 층이 낸 수를 그대로 모은다 — {@code PcapReader}(처리 패킷),
 * {@code FrameDecoder}(대상 외 패킷), {@code TrafficObserver}(대화 셋), {@code Reconciler}
 * (위반과 UNDECIDABLE 관찰). 어디서 몇이 나왔는지가 리포트 줄과 1:1 로 대응해야
 * 운영자가 수를 해석할 수 있다.
 */
final class Pipeline {

    private Pipeline() {
    }

    static Report run(byte[] pcap, String policyYaml) {
        // 정책을 먼저 읽는다 — 계약 오류는 캡처를 해독하기 전에 시끄럽게 실패해야 한다.
        CommunicationPolicy policy = PolicyLoader.parse(policyYaml);

        List<CapturedPacket> packets = PcapReader.read(pcap);
        DecodedFrames frames = FrameDecoder.decode(packets);
        List<TcpStream> streams = TcpStreamAssembler.assemble(frames.segments());
        ObservationResult observed = TrafficObserver.observe(streams);
        ReconcileResult reconciled = new Reconciler(policy).reconcile(observed.observations());

        return new Report(
            packets.size(),
            frames.skipped(),
            observed.decodedConversations(),
            observed.skippedConversations(),
            observed.undecidableConversations(),
            reconciled.undecidableCount(),
            observed.unobservedBytes(),
            observed.industrialBytes(),
            reconciled.findings());
    }
}
