package com.gameplatform.apigateway.security;

import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class KeycloakAuthoritiesExtractorTest {

    private final KeycloakAuthoritiesExtractor extractor = new KeycloakAuthoritiesExtractor();

    @Test
    void extractsAndNormalizesRealmRoles() {
        Map<String, Object> claims = Map.of(
                "realm_access", Map.of("roles", List.of("admin", "ROLE_user", "admin", " "))
        );

        assertThat(extractor.extract(claims))
                .extracting(GrantedAuthority::getAuthority)
                .containsExactly("ROLE_admin", "ROLE_user");
    }

    @Test
    void returnsEmptyAuthoritiesForMalformedClaims() {
        assertThat(extractor.extract(Map.of("realm_access", "invalid"))).isEmpty();
        assertThat(extractor.extract(Map.of())).isEmpty();
    }
}
