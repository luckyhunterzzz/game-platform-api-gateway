package com.gameplatform.apigateway.filters;

import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.UUID;

/**
 * Global filter that adds a unique ID to every request.
 * This ID (X-Request-Id) helps to track the request across all microservices.
 */
@Slf4j
@Component
public class CorrelationIdFilter implements GlobalFilter, Ordered {

    public static final String X_REQUEST_ID = "X-Request-Id";

    /**
     * Generates a new unique ID, adds it to the request and response.
     *
     * @param exchange the current server exchange
     * @param chain the filter chain
     * @return a Mono that signals when the processing is finished
     */
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String requestId = UUID.randomUUID().toString();

        log.debug("Tracing request {}: {} {}", requestId,
                exchange.getRequest().getMethod(),
                exchange.getRequest().getURI().getPath());

        exchange.getResponse().getHeaders().set(X_REQUEST_ID, requestId);

        ServerWebExchange mutatedExchange = exchange
                .mutate()
                .request(exchange.getRequest().mutate()
                        .headers(headers -> headers.remove(X_REQUEST_ID))
                        .header(X_REQUEST_ID, requestId).build())
                .build();

        return chain.filter(mutatedExchange);
    }

    /**
     * Sets the filter order.
     */
    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE;
    }
}
