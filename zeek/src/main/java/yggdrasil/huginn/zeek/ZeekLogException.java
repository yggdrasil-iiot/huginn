package yggdrasil.huginn.zeek;

/** 로그를 읽을 수 없거나 Huginn 이 기대한 형식이 아니다. 절반만 읽고 대사하지 않는다. */
public class ZeekLogException extends RuntimeException {

    public ZeekLogException(String message) {
        super(message);
    }
}
