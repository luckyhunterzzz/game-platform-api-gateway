package com.gameplatform.apigateway.security;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;

import static org.assertj.core.api.Assertions.assertThat;

class SessionCsrfProtectionMatcherTest {

    private final SessionCsrfProtectionMatcher matcher = new SessionCsrfProtectionMatcher();

    @Test
    void doesNotRequireCsrfForSafeMethods() {
        MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/api/session"));

        assertThat(matcher.matches(exchange).block().isMatch()).isFalse();
    }

    @Test
    void doesNotRequireCsrfForLegacyBearerRequests() {
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.method(HttpMethod.POST, "/api/v1/admin/test")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer token")
        );

        assertThat(matcher.matches(exchange).block().isMatch()).isFalse();
    }

    @Test
    void requiresCsrfForUnsafeSessionRequests() {
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.method(HttpMethod.POST, "/api/v1/admin/test")
        );

        assertThat(matcher.matches(exchange).block().isMatch()).isTrue();
    }
}
