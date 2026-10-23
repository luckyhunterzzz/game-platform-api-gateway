package com.gameplatform.apigateway.security;

import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class KeycloakOidcUserServiceTest {

    @Test
    void buildsUserFromTokensWithoutCallingUserInfoEndpoint() {
        Instant issuedAt = Instant.now();
        Instant expiresAt = issuedAt.plusSeconds(300);
        ReactiveJwtDecoder jwtDecoder = token -> Mono.just(Jwt.withTokenValue(token)
                .header("alg", "RS256")
                .subject("user-1")
                .issuedAt(issuedAt)
                .expiresAt(expiresAt)
                .claim("realm_access", Map.of("roles", List.of("admin")))
                .build());
        KeycloakOidcUserService userService = new KeycloakOidcUserService(
                jwtDecoder,
                new KeycloakAuthoritiesExtractor()
        );
        OidcIdToken idToken = new OidcIdToken(
                "id-token",
                issuedAt,
                expiresAt,
                Map.of(
                        "sub", "user-1",
                        "preferred_username", "admin_user",
                        "email", "admin@example.com"
                )
        );
        OAuth2AccessToken accessToken = new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER,
                "access-token",
                issuedAt,
                expiresAt,
                java.util.Set.of("openid", "profile", "email")
        );

        var user = userService.loadUser(new OidcUserRequest(clientRegistration(), accessToken, idToken)).block();

        assertThat(user).isNotNull();
        assertThat(user.getPreferredUsername()).isEqualTo("admin_user");
        assertThat(user.getEmail()).isEqualTo("admin@example.com");
        assertThat(user.getUserInfo()).isNull();
        assertThat(user.getAuthorities())
                .extracting(GrantedAuthority::getAuthority)
                .contains("ROLE_admin");
    }

    private ClientRegistration clientRegistration() {
        return ClientRegistration.withRegistrationId("keycloak")
                .clientId("game-gateway")
                .clientSecret("secret")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("http://localhost:8081/login/oauth2/code/keycloak")
                .scope("openid", "profile", "email")
                .authorizationUri("http://localhost:8080/realms/game-realm/protocol/openid-connect/auth")
                .tokenUri("http://keycloak:8080/realms/game-realm/protocol/openid-connect/token")
                .jwkSetUri("http://keycloak:8080/realms/game-realm/protocol/openid-connect/certs")
                .userInfoUri("http://127.0.0.1:1/unreachable")
                .userNameAttributeName("preferred_username")
                .clientName("Keycloak")
                .build();
    }
}
