# 🛡️ Game Ops Platform - API Gateway

The API Gateway is the BFF and the only public entry point for the Game Ops Platform. It owns browser authentication, Redis-backed user sessions, route authorization, and trusted user headers for internal services.

## Security flow

1. The browser opens `GET /oauth2/authorization/keycloak`.
2. Keycloak authenticates the user and redirects to `/login/oauth2/code/keycloak`.
3. The Gateway stores the `SecurityContext` and `OAuth2AuthorizedClient` in a Redis `WebSession`.
4. The browser receives only the persistent `GAME_SESSION` cookie. Access and refresh tokens are not exposed to JavaScript.
5. Before route authorization, the Gateway refreshes an expiring access token and updates the roles in the session.
6. Internal services receive trusted `X-User-*` headers after the Gateway removes any client-supplied values.

The old Bearer JWT resource-server flow is temporarily supported during migration. Unsafe Bearer requests do not require CSRF because the token is not ambient browser authority. Cookie-session requests require the `X-XSRF-TOKEN` header.

## Browser endpoints

| Endpoint | Purpose |
| :--- | :--- |
| `GET /oauth2/authorization/keycloak` | Start Keycloak login |
| `GET /api/session` | Return authentication state and current user |
| `GET /api/session/csrf` | Create/return the CSRF token |
| `POST /api/logout` | Invalidate the Gateway session and end the Keycloak session |

`POST /api/logout` and all other unsafe cookie-authenticated requests must include the CSRF token from the `XSRF-TOKEN` cookie in the `X-XSRF-TOKEN` header.

## Refresh behavior

| Situation | Result |
| :--- | :--- |
| Access token is valid and Keycloak is temporarily unavailable | Continue with the current session |
| Access token is expired and Keycloak is temporarily unavailable | `503`, keep the Redis session and cookie |
| Refresh token is revoked or returns `invalid_grant` | Remove the authorized client, invalidate the session, return `401` |
| Required role is missing | `403` |

A short Redis lock prevents two Gateway instances from rotating the same refresh token at the same time.

## Identity propagation

The Gateway injects these headers into downstream requests:

- `X-Request-Id`
- `X-User-Id`
- `X-User-Username`
- `X-User-Email`
- `X-User-Roles`

Downstream services must not be reachable directly from an untrusted network.

## Configuration

Required development variables are provided by `game-platform-infra`:

```text
GAME_GATEWAY_CLIENT_SECRET
SPRING_DATA_REDIS_HOST
SPRING_DATA_REDIS_PORT
SPRING_DATA_REDIS_PASSWORD
```

Important optional settings:

```text
APP_SECURITY_FRONTEND_BASE_URL=http://localhost:3000
APP_SECURITY_KEYCLOAK_LOGOUT_URI=http://localhost:8080/realms/game-realm/protocol/openid-connect/logout
APP_SECURITY_REFRESH_CLOCK_SKEW=60s
APP_SECURITY_REFRESH_LOCK_TTL=30s
APP_SECURITY_REFRESH_REQUEST_TIMEOUT=10s
SERVER_REACTIVE_SESSION_TIMEOUT=7d
SERVER_REACTIVE_SESSION_COOKIE_NAME=GAME_SESSION
SERVER_REACTIVE_SESSION_COOKIE_MAX_AGE=7d
SERVER_REACTIVE_SESSION_COOKIE_SECURE=false
```

The cookie `Max-Age` and Redis session timeout should stay aligned. With the default `7d` values, closing and reopening the browser does not end an otherwise valid session.

Production must use HTTPS and a secure `__Host-...` session cookie with `Path=/` and no `Domain` attribute.

## Verification

```bash
./mvnw -D"maven.compiler.release=17" test
```

The release override is needed only on a workstation that currently runs JDK 17. The application and Docker image target Java 21.
