package com.gameplatform.apigateway.security;

import org.junit.jupiter.api.Test;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class SessionSerializationTest {

    @Test
    void serializesSecurityContextAndAuthorizedClientForRedisSession() throws IOException {
        Instant issuedAt = Instant.parse("2026-01-01T00:00:00Z");
        Instant expiresAt = issuedAt.plusSeconds(900);
        DefaultOidcUser user = new DefaultOidcUser(
                List.of(new SimpleGrantedAuthority("ROLE_admin")),
                new OidcIdToken(
                        "id-token",
                        issuedAt,
                        expiresAt,
                        Map.of("sub", "user-1", "preferred_username", "admin")
                )
        );
        OAuth2AuthenticationToken authentication = new OAuth2AuthenticationToken(
                user,
                user.getAuthorities(),
                "keycloak"
        );
        SecurityContextImpl securityContext = new SecurityContextImpl(authentication);

        OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(
                clientRegistration(),
                "user-1",
                new OAuth2AccessToken(
                        OAuth2AccessToken.TokenType.BEARER,
                        "access-token",
                        issuedAt,
                        expiresAt,
                        Set.of("openid")
                ),
                new OAuth2RefreshToken("refresh-token", issuedAt, issuedAt.plusSeconds(604800))
        );

        assertThat(serialize(securityContext)).isNotEmpty();
        assertThat(serialize(Map.of("keycloak", authorizedClient))).isNotEmpty();
    }

    private byte[] serialize(Object value) throws IOException {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        try (ObjectOutputStream objectOutput = new ObjectOutputStream(output)) {
            objectOutput.writeObject(value);
        }
        return output.toByteArray();
    }

    private ClientRegistration clientRegistration() {
        return ClientRegistration.withRegistrationId("keycloak")
                .clientId("game-gateway")
                .clientSecret("secret")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
                .authorizationUri("http://localhost/authorize")
                .tokenUri("http://localhost/token")
                .jwkSetUri("http://localhost/certs")
                .userInfoUri("http://localhost/userinfo")
                .userNameAttributeName("sub")
                .clientName("Keycloak")
                .build();
    }
}
