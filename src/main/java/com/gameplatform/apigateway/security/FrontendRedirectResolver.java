package com.gameplatform.apigateway.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;

@Component
public class FrontendRedirectResolver {

    private static final String AUTHENTICATION_ERROR = "oauth2_login_failed";

    private final URI defaultFrontendUri;
    private final URI ruFrontendUri;
    private final String ruApiHost;

    public FrontendRedirectResolver(
            @Value("${app.security.frontend-base-url}") String defaultFrontendBaseUrl,
            @Value("${app.security.ru-frontend-base-url}") String ruFrontendBaseUrl,
            @Value("${app.security.ru-api-base-url}") String ruApiBaseUrl
    ) {
        this.defaultFrontendUri = requireHttpUri(defaultFrontendBaseUrl, "frontend base URL");
        this.ruFrontendUri = requireHttpUri(ruFrontendBaseUrl, "RU frontend base URL");
        this.ruApiHost = requireHttpUri(ruApiBaseUrl, "RU API base URL").getHost();
    }

    public URI resolveFrontend(ServerWebExchange exchange) {
        String requestHost = exchange.getRequest().getURI().getHost();
        return requestHost != null && requestHost.equalsIgnoreCase(ruApiHost)
                ? ruFrontendUri
                : defaultFrontendUri;
    }

    public URI resolveAuthenticationFailure(ServerWebExchange exchange) {
        return UriComponentsBuilder.fromUri(resolveFrontend(exchange))
                .queryParam("authError", AUTHENTICATION_ERROR)
                .build()
                .encode()
                .toUri();
    }

    private static URI requireHttpUri(String value, String propertyName) {
        URI uri = URI.create(value);
        boolean validScheme = "http".equalsIgnoreCase(uri.getScheme())
                || "https".equalsIgnoreCase(uri.getScheme());

        if (!validScheme || uri.getHost() == null || uri.getRawQuery() != null || uri.getRawFragment() != null) {
            throw new IllegalArgumentException(propertyName + " must be an absolute HTTP(S) URL without query or fragment");
        }

        return uri;
    }
}
