# Service tokens for `/uid` lookup

The `/uid` endpoint requires a valid **Bearer token** for the realm. For machine-to-machine
calls (for example from `PosixMapperClient` or internal services), use the OIDC **client
credentials** grant to obtain a service token.

The `/uid` endpoint validates that the token is issued by the realm; it does **not** require
POSIX claims inside the JWT. Lookup is driven by query parameters (`user`, `uid`), not by
token identity.

For POSIX attributes **embedded in access tokens** (other internal services), see
[POSIX token claims](POSIX-Token-Claims.md).

## Token endpoint

With `http-relative-path=/ums` and realm `master`:

```http
POST http://localhost:8080/ums/realms/master/protocol/openid-connect/token
Content-Type: application/x-www-form-urlencoded
```

OpenID discovery (lists `token_endpoint` and related URLs):

```http
GET http://localhost:8080/ums/realms/master/.well-known/openid-configuration
```

Replace host, port, and realm for your deployment.

## 1. Create a confidential client (one-time)

In the Keycloak admin console (`http://localhost:8080/ums/admin`):

1. Open **Clients → Create client**.
2. Set **Client ID** (for example `ums-service`).
3. Enable **Client authentication** (confidential client).
4. Enable **Service accounts roles**.
5. Save, open the **Credentials** tab, and copy the **Client secret**.

Direct access grants are **not** required for client credentials.

The bootstrap admin account (`KC_BOOTSTRAP_ADMIN_*`) is for the admin console only; it is
not used for service tokens.

## 2. Request a service token

```bash
curl -s -X POST "http://localhost:8080/ums/realms/master/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials" \
  -d "client_id=ums-service" \
  -d "client_secret=YOUR_CLIENT_SECRET"
```

Store the access token:

```bash
export TOKEN=$(curl -s -X POST "http://localhost:8080/ums/realms/master/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials" \
  -d "client_id=ums-service" \
  -d "client_secret=YOUR_CLIENT_SECRET" | jq -r .access_token)
```

## 3. Call `/uid`

```bash
curl -H "Authorization: Bearer $TOKEN" \
  -H "Accept: text/tab-separated-values" \
  "http://localhost:8080/ums/realms/master/posix/uid?user=jsmith"
```

## Notes

| Topic | Detail |
|-------|--------|
| Token subject | Client-credentials tokens represent the client's **service account**, not a human user |
| Scopes | No special scope is required for `/uid` authentication |
| User tokens | Browser or IdP login flows use the authorization code grant; see [INDIGO IAM (SKA IAM) setup](INDIGO-IAM-SKAIAM-Setup.md) |
| POSIX in JWT | Map `posix.*` claims via [POSIX token claims](POSIX-Token-Claims.md) when downstream services need identity in the token itself |
