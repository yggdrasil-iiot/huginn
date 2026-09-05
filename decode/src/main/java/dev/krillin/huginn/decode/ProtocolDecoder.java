package dev.krillin.huginn.decode;

import dev.krillin.huginn.pcap.TcpStream;
import dev.krillin.huginn.reconcile.Protocol;

import java.util.List;

/**
 * 이음매. <b>프로토콜 지식은 전부 이 뒤에 있다.</b>
 *
 * <p>1차 설계 §10 의 반증 조건이 이 인터페이스를 겨냥한다 — 두 번째 프로토콜을 붙일 때
 * {@code decode} 밖이 바뀌어야 하면 {@code Observation} 이음매를 잘못 잡은 것이다.
 */
interface ProtocolDecoder {

    Protocol protocol();

    /** 이 스트림에서 이 프로토콜의 프레임이 몇 개 나오는가. */
    StreamEvidence scan(TcpStream stream);

    /**
     * 대화에서 요청 관찰을 만든다. 방향 판정 방식은 프로토콜마다 다르므로 여기 안에 있다.
     *
     * @param conversation 이 대화의 <b>모든</b> 스트림. {@code frameCount == 0} 인 것도 빼지 않는다 —
     *                     Modbus 의 R5(고른 방향이 캡처에 없음) 판정이 그 부재를 봐야 성립한다.
     *                     순서는 입력 목록에 처음 등장한 순서다.
     */
    Decoded decode(List<StreamEvidence> conversation);
}
