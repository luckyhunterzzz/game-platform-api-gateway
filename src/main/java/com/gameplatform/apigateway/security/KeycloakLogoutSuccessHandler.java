package com.gameplatform.apigateway.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.logout.ServerLogoutSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;
import reactor.core.publisher.Mono;

import java.net.URI;

@Component
public class KeycloakLogoutSuccessHandler implements ServerLogoutSuccessHandler {

    private final String keycloakLogoutUri;
    private final String clientId;
    private final FrontendRedirectResolver frontendRedirectResolver;

    public KeycloakLogoutSuccessHandler(
            @Value("${app.security.keycloak-logout-uri}") String keycloakLogoutUri,
            @Value("${spring.security.oauth2.client.registration.keycloak.client-id}") String clientId,
            FrontendRedirectResolver frontendRedirectResolver
    ) {
        this.keycloakLogoutUri = keycloakLogoutUri;
        this.clientId = clientId;
        this.frontendRedirectResolver = frontendRedirectResolver;
    }

    @Override
    public Mono<Void> onLogoutSuccess(WebFilterExchange webFilterExchange, Authentication authentication) {
        URI redirectUri = buildRedirectUri(webFilterExchange, authentication);
        webFilterExchange.getExchange().getResponse().setStatusCode(HttpStatus.SEE_OTHER);
        webFilterExchange.getExchange().getResponse().getHeaders().setLocation(redirectUri);
        return webFilterExchange.getExchange().getResponse().setComplete();
    }

    private URI buildRedirectUri(WebFilterExchange webFilterExchange, Authentication authentication) {
        URI frontendUri = frontendRedirectResolver.resolveFrontend(webFilterExchange.getExchange());
        UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(keycloakLogoutUri)
                .queryParam("client_id", clientId)
                .queryParam("post_logout_redirect_uri", frontendUri);

        if (authentication != null && authentication.getPrincipal() instanceof OidcUser oidcUser) {
            builder.queryParam("id_token_hint", oidcUser.getIdToken().getTokenValue());
        }

        return builder.build().encode().toUri();
    }
}
