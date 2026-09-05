package dev.krillin.huginn.contract;

import java.util.EnumSet;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import com.fasterxml.jackson.core.JacksonException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;

import dev.krillin.huginn.contract.CommunicationPolicy.Key;
import dev.krillin.huginn.reconcile.Access;

/**
 * YAML 로 선언된 통신 정책을 읽고 검증한다.
 *
 * 계약 오류는 즉시, 시끄럽게 실패한다 — 절반만 이해한 정책을 통과시키면
 * deny-by-default 때문에 정상 통신 전부가 위반으로 보고된다.
 */
public class PolicyLoader {

    private static final int SUPPORTED_VERSION = 1;

    private PolicyLoader() {}

    public static CommunicationPolicy parse(String yaml) {
        PolicyDocument doc;
        try {
            ObjectMapper mapper = new ObjectMapper(new YAMLFactory());
            doc = mapper.readValue(yaml, PolicyDocument.class);
        } catch (JacksonException e) {
            throw new PolicyException("정책 YAML을 읽을 수 없다: " + e.getMessage(), e);
        }

        if (doc.version() != SUPPORTED_VERSION) {
            throw new PolicyException("지원하지 않는 정책 version: " + doc.version()
                    + " (지원: " + SUPPORTED_VERSION + ")");
        }
        if (doc.peers() == null) {
            throw new PolicyException("정책에 peers 가 없다");
        }
        if (doc.allowed() == null) {
            throw new PolicyException("정책에 allowed 가 없다");
        }

        Map<String, String> peerAddressById = new HashMap<>();
        Map<String, String> peerIdByAddress = new HashMap<>();
        for (PolicyDocument.Peer peer : doc.peers()) {
            if (peerAddressById.containsKey(peer.id())) {
                throw new PolicyException("peer id 중복: " + peer.id());
            }
            if (peerIdByAddress.containsKey(peer.address())) {
                throw new PolicyException("peer 주소 중복: " + peer.address()
                        + " (id: " + peerIdByAddress.get(peer.address()) + ", " + peer.id() + ")");
            }
            peerAddressById.put(peer.id(), peer.address());
            peerIdByAddress.put(peer.address(), peer.id());
        }

        Map<Key, Set<Access>> table = new HashMap<>();
        for (PolicyDocument.Rule rule : doc.allowed()) {
            String fromAddress = peerAddressById.get(rule.from());
            if (fromAddress == null) {
                throw new PolicyException("알 수 없는 peer 참조 (from): " + rule.from());
            }
            String toAddress = peerAddressById.get(rule.to());
            if (toAddress == null) {
                throw new PolicyException("알 수 없는 peer 참조 (to): " + rule.to());
            }

            Key key = new Key(fromAddress, toAddress, rule.protocol());
            Set<Access> access = table.computeIfAbsent(key, k -> EnumSet.noneOf(Access.class));
            access.addAll(rule.access());
        }

        return new CommunicationPolicy(table);
    }
}
