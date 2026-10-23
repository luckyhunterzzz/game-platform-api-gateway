package com.gameplatform.apigateway;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
import org.springframework.session.ReactiveSessionRepository;
import org.springframework.web.server.session.WebSessionManager;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(properties = {
        "spring.security.oauth2.resourceserver.jwt.issuer-uri=http://localhost:9999/realms/test",
        "spring.security.oauth2.client.registration.keycloak.client-secret=test-secret",
        "spring.data.redis.host=localhost",
        "spring.data.redis.port=6379",
        "sentry.dsn="
})
class GatewaySecurityContextTest {

    @Autowired
    private WebSessionManager webSessionManager;

    @Autowired
    private ReactiveSessionRepository<?> sessionRepository;

    @Autowired
    private ServerOAuth2AuthorizedClientRepository authorizedClientRepository;

    @Autowired
    private ServerProperties serverProperties;

    @Test
    void configuresRedisWebSessionsAndSessionAuthorizedClients() {
        assertThat(webSessionManager).isNotNull();
        assertThat(sessionRepository.getClass().getSimpleName()).contains("Redis");
        assertThat(authorizedClientRepository.getClass().getSimpleName()).contains("WebSession");
    }

    @Test
    void configuresPersistentSessionCookieForSevenDays() {
        var cookie = serverProperties.getReactive().getSession().getCookie();

        assertThat(cookie.getName()).isEqualTo("GAME_SESSION");
        assertThat(cookie.getMaxAge()).isEqualTo(Duration.ofDays(7));
        assertThat(cookie.getPath()).isEqualTo("/");
        assertThat(cookie.getHttpOnly()).isTrue();
    }
}
