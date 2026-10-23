package com.gameplatform.apigateway.security;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcReactiveOAuth2UserService;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.userinfo.ReactiveOAuth2UserService;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import reactor.core.publisher.Mono;

import java.util.Collection;
import java.util.LinkedHashSet;

public class KeycloakOidcUserService implements ReactiveOAuth2UserService<OidcUserRequest, OidcUser> {

    private final OidcReactiveOAuth2UserService delegate = new OidcReactiveOAuth2UserService();
    private final ReactiveJwtDecoder jwtDecoder;
    private final KeycloakAuthoritiesExtractor authoritiesExtractor;

    public KeycloakOidcUserService(
            ReactiveJwtDecoder jwtDecoder,
            KeycloakAuthoritiesExtractor authoritiesExtractor
    ) {
        this.jwtDecoder = jwtDecoder;
        this.authoritiesExtractor = authoritiesExtractor;
        this.delegate.setRetrieveUserInfo(userRequest -> false);
    }

    @Override
    public Mono<OidcUser> loadUser(OidcUserRequest userRequest) {
        Mono<OidcUser> oidcUser = delegate.loadUser(userRequest);
        Mono<Collection<GrantedAuthority>> keycloakAuthorities = jwtDecoder
                .decode(userRequest.getAccessToken().getTokenValue())
                .map(jwt -> authoritiesExtractor.extract(jwt.getClaims()));

        return Mono.zip(oidcUser, keycloakAuthorities)
                .map(tuple -> mergeAuthorities(tuple.getT1(), tuple.getT2()));
    }

    private OidcUser mergeAuthorities(OidcUser user, Collection<GrantedAuthority> keycloakAuthorities) {
        LinkedHashSet<GrantedAuthority> authorities = new LinkedHashSet<>(user.getAuthorities());
        authorities.addAll(keycloakAuthorities);

        if (user.getUserInfo() == null) {
            return new DefaultOidcUser(authorities, user.getIdToken());
        }
        return new DefaultOidcUser(authorities, user.getIdToken(), user.getUserInfo());
    }
}
