package com.gameplatform.apigateway.security;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.web.server.WebFilterExchange;
import reactor.core.publisher.Mono;

import static org.assertj.core.api.Assertions.assertThat;

class KeycloakLogoutSuccessHandlerTest {

    private final FrontendRedirectResolver redirectResolver = new FrontendRedirectResolver(
            "https://gameops-platform.dev",
            "https://ru.gameops-platform.dev",
            "https://ru-api.gameops-platform.dev"
    );
    private final KeycloakLogoutSuccessHandler handler = new KeycloakLogoutSuccessHandler(
            "https://auth.gameops-platform.dev/realms/game-realm/protocol/openid-connect/logout",
            "game-gateway",
            redirectResolver
    );

    @Test
    void redirectsRuLogoutThroughKeycloakBackToRuFrontend() {
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.post("https://ru-api.gameops-platform.dev/api/logout")
        );
        WebFilterExchange webFilterExchange = new WebFilterExchange(exchange, ignored -> Mono.empty());

        handler.onLogoutSuccess(webFilterExchange, null).block();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.SEE_OTHER);
        assertThat(exchange.getResponse().getHeaders().getLocation())
                .hasToString("https://auth.gameops-platform.dev/realms/game-realm/protocol/openid-connect/logout"
                        + "?client_id=game-gateway"
                        + "&post_logout_redirect_uri=https://ru.gameops-platform.dev");
    }
}
