package dev.krillin.huginn.pcap;

import java.io.ByteArrayOutputStream;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * {@link TcpSegment} 목록을 방향(4-tuple)별로 묶어 {@link TcpStream} 으로 재조립한다.
 * <p>길이 0 세그먼트는 바이트를 기여하지 않는다 — 단, {@code syn && !ack} 인 세그먼트는
 * 그 방향의 스트림을 등록하고 {@link TcpStream#sawSynOnly()} 를 세우는 유일한 예외다.
 * 그 외 길이 0 세그먼트(순수 ACK · FIN · SYN+ACK)는 스트림 등록조차 하지 않는다.
 * <p>{@code LinkedHashMap} 으로 모아 방향이 최초로 등장한 순서를 그대로 유지한다 —
 * 리포트의 결정성이 여기서 시작된다.
 */
public final class TcpStreamAssembler {

    private TcpStreamAssembler() {
    }

    public static List<TcpStream> assemble(List<TcpSegment> segments) {
        Map<StreamKey, Builder> streams = new LinkedHashMap<>();

        for (TcpSegment segment : segments) {
            boolean hasBytes = segment.payload().length > 0;
            boolean synOnly = segment.syn() && !segment.ack();
            if (!hasBytes && !synOnly) {
                continue;
            }
            StreamKey key = new StreamKey(segment.sourceAddress(), segment.sourcePort(),
                segment.targetAddress(), segment.targetPort());
            Builder builder = streams.computeIfAbsent(key, k -> new Builder());
            if (builder.at == null || segment.at().isBefore(builder.at)) {
                builder.at = segment.at();
            }
            if (segment.truncated()) {
                builder.truncated = true;
            }
            if (synOnly) {
                builder.sawSynOnly = true;
            }
            if (hasBytes) {
                builder.dataSegments.add(segment);
            }
        }

        List<TcpStream> result = new ArrayList<>(streams.size());
        for (Map.Entry<StreamKey, Builder> entry : streams.entrySet()) {
            StreamKey key = entry.getKey();
            Builder builder = entry.getValue();
            result.add(new TcpStream(builder.at, key.sourceAddress(), key.sourcePort(),
                key.targetAddress(), key.targetPort(),
                builder.contiguousPrefix(), builder.hasGap(),
                builder.truncated, builder.sawSynOnly));
        }
        return result;
    }

    private record StreamKey(String sourceAddress, int sourcePort, String targetAddress, int targetPort) {
    }

    private static final class Builder {
        Instant at;
        boolean truncated;
        boolean sawSynOnly;
        final List<TcpSegment> dataSegments = new ArrayList<>();

        private byte[] prefix;
        private boolean gap;
        private boolean computed;

        byte[] contiguousPrefix() {
            compute();
            return prefix;
        }

        boolean hasGap() {
            compute();
            return gap;
        }

        private void compute() {
            if (computed) {
                return;
            }
            computed = true;
            if (dataSegments.isEmpty()) {
                prefix = new byte[0];
                gap = false;
                return;
            }
            // stable sort by seq alone — equal-seq ties keep input order, which is what lets
            // "first wins" resolve a retransmission-disguise deterministically.
            dataSegments.sort(java.util.Comparator.comparingLong(TcpSegment::sequence));

            long base = dataSegments.get(0).sequence();
            long nextSeq = base;
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            boolean sawGap = false;
            for (TcpSegment segment : dataSegments) {
                long segStart = segment.sequence();
                long segEnd = segStart + segment.payload().length;
                if (segStart > nextSeq) {
                    sawGap = true;
                    break;
                }
                if (segEnd <= nextSeq) {
                    // fully covered by bytes already assembled — first-wins, nothing new here.
                    continue;
                }
                int skip = (int) (nextSeq - segStart);
                out.write(segment.payload(), skip, segment.payload().length - skip);
                nextSeq = segEnd;
            }
            prefix = out.toByteArray();
            gap = sawGap;
        }
    }
}
