package dev.krillin.huginn.decode;

import dev.krillin.huginn.pcap.TcpStream;
import dev.krillin.huginn.reconcile.Endpoint;
import dev.krillin.huginn.reconcile.Observation;
import dev.krillin.huginn.reconcile.Protocol;

import java.util.ArrayList;
import java.util.List;

/**
 * S7comm 판정. <b>ROSCTR 이 방향을 선언한다.</b>
 *
 * <p>1차 Modbus 가 신호 둘(SYN·PDU 형태)과 결합 규칙 다섯(R1~R5)으로 하던 일을 필드 하나가
 * 대신한다 — ROSCTR 1(Job)이면 요청이고 3(Ack_Data)이면 응답이다. SYN 도, PDU 형태도, 신호
 * 결합도 필요 없고, 응답만 잡힌 단방향 캡처에도 별도 가드가 필요 없다.
 *
 * <p><b>기본 규칙:</b> Job 프레임을 실은 방향이 클라이언트다. 그런 방향이 <b>0 개거나 2 개면
 * 판정 불가</b>다. 0 개는 응답만 잡혔거나 Userdata 만 실린 경우이고, 2 개는 한 4-tuple 에 연결이
 * 둘 묶인 경우다 — 1차 S2 의 "양쪽이 같은 형태면 모순"과 같은 판단이다.
 *
 * <p><b>ROSCTR 7(Userdata)은 프레임으로 세되 관찰하지 않는다.</b> 요청/응답 구분이 파라미터
 * 안쪽에 또 있어 해석하지 않기 때문이다(설계 §5). 대신 {@code tailUndecidable} 을 세운다 —
 * 그 프레임은 <b>응답 방향에도 실리므로</b> client 의 잔여만 보는 순회기 규칙으로는 잡히지 않는다.
 * COTP 분할도 같은 이유로 같은 신호를 쓴다.
 *
 * <p><b>포트는 보지 않는다</b> — 102 라는 관례는 502 와 같은 이유로 쓰지 않는다.
 */
final class S7Decoder implements ProtocolDecoder {

    private static final int ROSCTR_JOB = 1;
    private static final int ROSCTR_USERDATA = 7;

    @Override
    public Protocol protocol() {
        return Protocol.S7COMM;
    }

    @Override
    public StreamEvidence scan(TcpStream stream) {
        RunReader.Reading<S7FramingResult> reading = read(stream);
        return new StreamEvidence(stream, framesOf(reading).size(), reading.unreadBytes(),
            reading.capturedBytes(), reading.rejectedRuns(), reading.dirtyRuns());
    }

    private static RunReader.Reading<S7FramingResult> read(TcpStream stream) {
        return RunReader.read(stream, S7Framer::frames);
    }

    /** 수용된 구간들의 프레임을 순서대로 이어 붙인다. */
    private static List<S7Frame> framesOf(RunReader.Reading<S7FramingResult> reading) {
        List<S7Frame> frames = new ArrayList<>();
        for (S7FramingResult one : reading.accepted()) {
            frames.addAll(one.frames());
        }
        return frames;
    }

    /**
     * COTP 분할은 <b>구간 수용 여부와 무관한 스트림의 사실</b>이라 거부된 구간의 것도 기여한다.
     * {@link RunReader} 는 수용된 것만 주므로 구간 전체를 따로 훑는다.
     */
    private static boolean anyFragmented(TcpStream stream) {
        for (byte[] run : stream.runs()) {
            if (S7Framer.frames(run).fragmented()) {
                return true;
            }
        }
        return false;
    }

    @Override
    public Decoded decode(List<StreamEvidence> conversation) {
        List<StreamEvidence> requestSides = new ArrayList<>();
        boolean unread = false;                        // Userdata 또는 COTP 분할

        for (StreamEvidence evidence : conversation) {
            unread |= anyFragmented(evidence.stream());
            boolean hasJob = false;
            for (S7Frame frame : framesOf(read(evidence.stream()))) {
                if (frame.rosctr() == ROSCTR_JOB) {
                    hasJob = true;
                } else if (frame.rosctr() == ROSCTR_USERDATA) {
                    unread = true;                     // 해석하지 않는다(설계 §5)
                }
            }
            if (hasJob) {
                requestSides.add(evidence);
            }
        }

        if (requestSides.size() != 1) {
            // 0 개(응답만·Userdata 만)와 2 개(연결이 둘)를 순회기는 구별할 수 없으므로 여기서 싣는다.
            return Decoded.undecided(requestSides.size() > 1);
        }

        StreamEvidence client = requestSides.get(0);
        List<Observation> observations = new ArrayList<>();
        for (S7Frame frame : framesOf(read(client.stream()))) {
            if (frame.rosctr() == ROSCTR_JOB) {
                observations.add(observationOf(client.stream(), frame));
            }
        }
        return new Decoded(observations, client, unread, false);
    }

    private static Observation observationOf(TcpStream stream, S7Frame frame) {
        return new Observation(
            stream.at(),
            new Endpoint(stream.sourceAddress(), stream.sourcePort()),
            new Endpoint(stream.targetAddress(), stream.targetPort()),
            Protocol.S7COMM,
            S7Access.of(frame.functionCode()),
            S7ObjectRef.of(frame.parameter()));        // 함수코드가 아니라 파라미터 전체다
    }
}
