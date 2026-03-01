# 🛡️ Game Ops Platform - API Gateway

The API Gateway is the central entry point for the GameOps Platform. It manages security, request routing, and identity propagation across the microservices ecosystem.

## ⚙️ Core Responsibilities

* **Authentication & JWT Validation:** Validates OIDC tokens issued by Keycloak.
* **RBAC (Role-Based Access Control):** Enforces security constraints based on JWT claims (e.g., `/admin/**` requires `admin` role).
* **Request Scrubbing:** Extracts user data from JWT and propagates it to downstream services via HTTP headers.
* **Routing:** Proxies requests to internal microservices (Main Service, etc.).

---

## 🔐 Security & Profiles

The service uses **Spring Boot Profiles** to handle different environments:

| Profile | Description | Issuer Validation |
| :--- | :--- | :--- |
| **`docker` (Prod)** | Strict security mode. Requires identical `iss` claim and configuration URI. | **Enabled** |
| **`dev` (Local)** | Flexible mode for development. Allows tokens from `localhost` while running in Docker. | **Disabled** (Timestamp only) |

### Identity Propagation
The Gateway extracts claims from the JWT and injects the following headers into every downstream request:
* `X-Request-Id`: Unique correlation ID for tracing.
* `X-User-Id`: Subject (UUID) from Keycloak.
* `X-User-Username`: Preferred username.
* `X-User-Roles`: Comma-separated list of roles (extracted from `realm_access`).



---

## 📡 Routing Configuration

Routes are defined in `application.yml`:

| Path Pattern | Target Service | Auth Required |
| :--- | :--- | :--- |
| `/api/v1/public/**` | Main Service | No |
| `/api/v1/admin/**` | Main Service | Yes (`ROLE_admin`) |
| `/api/v1/**` | Main Service | Yes |
| `/actuator/health` | Gateway (Self) | No |

---

## 🛠 Tech Stack

* **Framework:** Spring Boot 3.4+
* **Gateway:** Spring Cloud Gateway (WebFlux)
* **Security:** Spring Security OAuth2 Resource Server
* **Token Library:** Nimbus JOSE + JWT

---

## 🚀 Local Development

To run the gateway locally while connecting to Keycloak in Docker:

1.  Ensure Infrastructure is running: `docker compose up -d`
2.  Start with `dev` profile:
    ```bash
    ./mvnw spring-boot:run -Dspring-boot.run.profiles=dev
    ```
    *Or via IDE with VM Option:* `-Dspring.profiles.active=dev`

---

## 🛑 Important Implementation Note

When adding new routes, ensure they are placed **above** the catch-all patterns in `application.yml` to prevent predicate shadowing.
