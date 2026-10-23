package com.gameplatform.apigateway.security;

import org.junit.jupiter.api.Test;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;

import java.net.URI;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

class FrontendRedirectResolverTest {

    private final FrontendRedirectResolver resolver = new FrontendRedirectResolver(
            "https://gameops-platform.dev",
            "https://ru.gameops-platform.dev",
            "https://ru-api.gameops-platform.dev"
    );

    @Test
    void resolvesRuFrontendForRuApiHost() {
        MockServerWebExchange exchange = exchange("https://ru-api.gameops-platform.dev/login/oauth2/code/keycloak");

        assertThat(resolver.resolveFrontend(exchange))
                .isEqualTo(URI.create("https://ru.gameops-platform.dev"));
    }

    @Test
    void resolvesDefaultFrontendForMainAndUnknownHosts() {
        assertThat(resolver.resolveFrontend(exchange("https://api.gameops-platform.dev/login/oauth2/code/keycloak")))
                .isEqualTo(URI.create("https://gameops-platform.dev"));
        assertThat(resolver.resolveFrontend(exchange("https://untrusted.example/login/oauth2/code/keycloak")))
                .isEqualTo(URI.create("https://gameops-platform.dev"));
    }

    @Test
    void resolvesRuAuthenticationFailureWithoutAcceptingUserRedirects() {
        MockServerWebExchange exchange = exchange("https://ru-api.gameops-platform.dev/login/oauth2/code/keycloak");

        assertThat(resolver.resolveAuthenticationFailure(exchange))
                .isEqualTo(URI.create("https://ru.gameops-platform.dev?authError=oauth2_login_failed"));
    }

    @Test
    void rejectsInvalidConfiguredUrls() {
        assertThatIllegalArgumentException().isThrownBy(() -> new FrontendRedirectResolver(
                "javascript:alert(1)",
                "https://ru.gameops-platform.dev",
                "https://ru-api.gameops-platform.dev"
        ));
    }

    private MockServerWebExchange exchange(String url) {
        return MockServerWebExchange.from(MockServerHttpRequest.get(url));
    }
}
