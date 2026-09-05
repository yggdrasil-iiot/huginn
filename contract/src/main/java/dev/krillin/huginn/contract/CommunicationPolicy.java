package dev.krillin.huginn.contract;

import java.util.Map;
import java.util.Set;

import dev.krillin.huginn.reconcile.Access;
import dev.krillin.huginn.reconcile.Protocol;

/**
 * 검증을 마친 선언된 통신 정책. {@link PolicyLoader} 만이 만들 수 있다.
 *
 * deny-by-default: 조회표에 없으면 허용하지 않는다.
 */
public class CommunicationPolicy {

    /** (from 주소, to 주소, 프로토콜) → 허용된 access 집합. */
    record Key(String from, String to, Protocol protocol) {}

    private final Map<Key, Set<Access>> table;

    CommunicationPolicy(Map<Key, Set<Access>> table) {
        this.table = table;
    }

    public boolean allows(String from, String to, Protocol protocol, Access access) {
        if (access == Access.UNDECIDABLE) {
            return false;
        }
        Set<Access> allowed = table.get(new Key(from, to, protocol));
        return allowed != null && allowed.contains(access);
    }
}
