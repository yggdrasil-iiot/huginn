package dev.krillin.huginn.decode;

import dev.krillin.huginn.pcap.TcpStream;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;

/**
 * 스트림의 구간들을 프레이밍하고 <b>수용된 것만</b> 낸다.
 *
 * <p><b>수용 규칙이 이 클래스의 전부이고, 그 한 줄이 1차 원칙과의 경계선이다.</b> 첫 구간은
 * 조건 없이 받고, 이후 구간은 프레임이 하나 이상이고 잔여가 0 일 때만 받는다.
 *
 * <p>경계를 <b>찾지</b> 않으므로 1차가 거부한 재동기화가 아니다 — 각 구간의 오프셋 0 하나만
 * 시도하고 끝까지 정확히 떨어질 때만 받는다. 중간부터 시작한 구간은 거의 확실히 걸러진다.
 * 실캡처 세 개에서 프레임이 나온 갭 이후 구간은 전부 잔여 0 이었다.
 *
 * <p>여섯 호출부가 전부 이것을 부른다. 각자 규칙을 적용하면 방향 판정이 자기 증거와 어긋난다 —
 * {@code scan} 이 거부한 구간의 프레임을 {@code shapeSignal} 이 보는 식이다.
 */
final class RunReader {

    private RunReader() {
    }

    static <F extends Framing> Reading<F> read(TcpStream stream, Function<byte[], F> framer) {
        List<F> accepted = new ArrayList<>();
        long unread = 0;
        long captured = 0;
        int rejected = 0;
        int dirty = 0;

        List<byte[]> runs = stream.runs();
        for (int i = 0; i < runs.size(); i++) {
            byte[] run = runs.get(i);
            captured += run.length;
            F framing = framer.apply(run);

            if (i == 0) {
                accepted.add(framing);
                unread += framing.leftoverBytes();     // 첫 구간은 지금 동작 그대로
                continue;
            }
            if (framing.frameCount() > 0 && framing.leftoverBytes() == 0) {
                accepted.add(framing);
                continue;
            }

            rejected++;
            if (framing.frameCount() > 0) {
                dirty++;
                unread += run.length;      // 읽을 수 있었으나 믿지 못해 통째로 버렸다
            } else {
                // 프레임이 없다. 잔여만 센다 — 연결 설정만 든 구간은 0 이 되며, 그것이
                // 2차의 "비-S7 TPKT 는 미해독 바이트가 아니다" 원칙이다.
                unread += framing.leftoverBytes();
            }
        }

        return new Reading<>(List.copyOf(accepted), unread, captured, rejected, dirty);
    }

    /**
     * @param accepted      수용된 구간의 프레이밍 결과(구간 순서). 프로토콜 고유 정보는
     *                      호출자가 구체 타입에서 꺼낸다
     * @param unreadBytes   받았지만 프레임이 덮지 못한 바이트
     * @param capturedBytes 이 스트림에서 실제로 받은 바이트. <b>구멍은 여기 들지 않는다</b>
     * @param rejectedRuns  거부한 구간 수
     * @param dirtyRuns     그중 프레임이 나왔던 구간 수 — 0 이어야 한다(설계 §7)
     */
    record Reading<F>(List<F> accepted, long unreadBytes, long capturedBytes,
                      int rejectedRuns, int dirtyRuns) {
    }
}
