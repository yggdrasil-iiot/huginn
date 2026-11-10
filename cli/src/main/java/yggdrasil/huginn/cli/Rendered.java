package yggdrasil.huginn.cli;

import yggdrasil.huginn.reconcile.Finding;

import java.util.List;

/** {@link Huginn} 이 출력하고 종료 코드를 정하는 데 필요한 것 — 입력이 pcap 이든 Zeek 로그든. */
interface Rendered {

    String render();

    List<Finding> findings();
}
