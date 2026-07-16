# POSIX attributes in OIDC tokens

This extension stores POSIX account details as Keycloak **user attributes**. To expose
those values to internal services, map them into JWT access tokens using a custom
**client scope** and **protocol mappers**.

There is no standard OIDC scope for POSIX attributes. Use a dedicated scope (this guide
uses `posix`) in addition to `openid`.

## Attributes to expose

| Keycloak user attribute | Suggested claim name | JSON type |
|-------------------------|----------------------|-----------|
| `posix.username` | `posix.username` | String |
| `posix.uidNumber` | `posix.uidNumber` | long |
| `posix.gidNumber` | `posix.gidNumber` | long |
| `posix.homeDirectory` | `posix.homeDirectory` | String |
| `posix.loginShell` | `posix.loginShell` | String |

Claim names may be shortened (for example `uidNumber` instead of `posix.uidNumber`) as
long as all mappers and consuming services use the same convention.

## Prerequisites

1. POSIX attributes must be populated on the user (via the **opencadc-posix** listener,
   LDAP mapper, or IdP attribute mapper).
2. In **Realm settings → General**, set **Unmanaged Attributes** to **Enabled** (or
   **Admin can edit**) so Keycloak can read custom `posix.*` attributes.

## 1. Create the client scope

1. Open **Client scopes → Create client scope**.
2. Configure:

   | Field | Value |
   |-------|--------|
   | Name | `posix` |
   | Description | POSIX account attributes for internal services |
   | Type | Default or Optional (see below) |
   | Protocol | `openid-connect` |
   | Display on consent screen | Off (internal scope) |
   | Include in token scope | On |

3. Save.

**Default** — tokens for assigned clients always include POSIX claims. Use this for
internal confidential clients that always need POSIX identity.

**Optional** — clients must request the scope explicitly (`scope=openid posix`). Use
this when only some token requests need POSIX claims.

## 2. Add protocol mappers

For each attribute in the table above:

1. Open **Client scopes → posix → Mappers → Add mapper → By configuration → User Attribute**.
2. Configure (example for `posix.uidNumber`):

   | Field | Value |
   |-------|--------|
   | Name | `posix-uidNumber` |
   | User Attribute | `posix.uidNumber` |
   | Token Claim Name | `posix.uidNumber` |
   | Claim JSON Type | long |
   | Add to ID token | Off |
   | Add to access token | On |
   | Add to userinfo | On |
   | Add to token introspection | On |
   | Multivalued | Off |

3. Save, then repeat for the remaining attributes (`String` type for all except the
   numeric UID/GID fields).

Map claims to the **access token** for resource servers. Include them in the **ID token**
only if a browser application needs POSIX fields directly.

## 3. Assign the scope to clients

1. Open **Clients → \<your internal client\> → Client scopes**.
2. Add `posix`:
   - **Default client scopes** if every token for this client should carry POSIX claims, or
   - **Optional client scopes** if callers must request `posix` explicitly.

Repeat for each internal service client that consumes POSIX identity from tokens.

## 4. Request tokens

Clients must request `openid` and, when `posix` is optional, the `posix` scope:

```http
POST /realms/{realm}/protocol/openid-connect/token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code
&client_id=my-service
&client_secret=...
&code=...
&redirect_uri=...
&scope=openid posix
```

For the resource-owner password grant (testing only):

```bash
curl -s -X POST "http://localhost:8080/realms/master/protocol/openid-connect/token" \
  -d "grant_type=password" \
  -d "client_id=YOUR_CLIENT" \
  -d "client_secret=YOUR_SECRET" \
  -d "username=USER" \
  -d "password=PASS" \
  -d "scope=openid posix" | jq -r .access_token
```

Decode the access token and confirm the POSIX claims are present.

## Scopes reference

| Scope | Purpose |
|-------|---------|
| `openid` | Required for OIDC; provides `sub`, `iss`, etc. |
| `posix` | Custom scope for this guide; carries `posix.*` claims |
| `profile` | Standard OIDC profile claims (`preferred_username`, `name`, …); **does not** include POSIX attributes |
| `email` | Standard email claims only |

The `profile` scope is used when **importing** IdP claims (for example
`preferred_username` → `posix.username` during broker login). See
[INDIGO IAM (SKA IAM) setup](INDIGO-IAM-SKAIAM-Setup.md). Outbound token mapping to
internal services uses the separate `posix` scope described here.

## Verify

1. In the Admin Console, open **Users → \<user\> → Attributes** and confirm POSIX
   attributes are set.
2. Obtain a token with `scope=openid posix` for a client that has the scope assigned.
3. Decode the JWT access token; expect claims such as:

   ```json
   {
     "sub": "...",
     "posix.username": "jsmith",
     "posix.uidNumber": 12345678,
     "posix.gidNumber": 12345678,
     "posix.homeDirectory": "/home/jsmith",
     "posix.loginShell": "/bin/nologin"
   }
   ```

If claims are missing, check that the user has attributes, the client has the `posix`
scope, the mappers are enabled on the access token, and **Unmanaged Attributes** is
enabled for the realm.

## Related documentation

- [README](../README.md) — attribute names and provisioning
- [Admin user creation](Admin-User-Creation.md) — how `posix.username` is set locally
- [INDIGO IAM (SKA IAM) setup](INDIGO-IAM-SKAIAM-Setup.md) — IdP claim import
