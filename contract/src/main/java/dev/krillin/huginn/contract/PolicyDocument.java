package dev.krillin.huginn.contract;

import java.util.List;
import dev.krillin.huginn.reconcile.Access;
import dev.krillin.huginn.reconcile.Protocol;

/** YAML 역직렬화 전용. 검증은 PolicyLoader 가 한다. */
record PolicyDocument(int version, List<Peer> peers, List<Rule> allowed) {
    record Peer(String id, String address) {}
    record Rule(String from, String to, Protocol protocol, List<Access> access) {}
}
