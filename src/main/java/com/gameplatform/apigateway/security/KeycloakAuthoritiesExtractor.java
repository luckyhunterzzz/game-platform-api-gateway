package com.gameplatform.apigateway.security;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;

@Component
public class KeycloakAuthoritiesExtractor {

    private static final String REALM_ACCESS = "realm_access";
    private static final String ROLES = "roles";
    private static final String ROLE_PREFIX = "ROLE_";

    public Collection<GrantedAuthority> extract(Map<String, Object> claims) {
        Object realmAccessValue = claims.get(REALM_ACCESS);
        if (!(realmAccessValue instanceof Map<?, ?> realmAccess)) {
            return Collections.emptyList();
        }

        Object rolesValue = realmAccess.get(ROLES);
        if (!(rolesValue instanceof List<?> roles)) {
            return Collections.emptyList();
        }

        LinkedHashSet<GrantedAuthority> authorities = new LinkedHashSet<>();
        for (Object roleValue : roles) {
            if (roleValue instanceof String role && !role.isBlank()) {
                String normalizedRole = role.startsWith(ROLE_PREFIX) ? role : ROLE_PREFIX + role;
                authorities.add(new SimpleGrantedAuthority(normalizedRole));
            }
        }
        return List.copyOf(authorities);
    }
}
