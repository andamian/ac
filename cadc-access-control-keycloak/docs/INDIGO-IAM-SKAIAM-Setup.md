# Keycloak with INDIGO IAM (SKA IAM prototype)

Step-by-step example for running the OpenCADC POSIX Keycloak image against the
[SKA IAM prototype](https://ska-iam.stfc.ac.uk/) INDIGO IAM instance. The same
pattern applies to other INDIGO IAM deployments that expose a standard OIDC
discovery document.

SKA IAM publishes OIDC metadata at
[https://ska-iam.stfc.ac.uk/.well-known/openid-configuration](https://ska-iam.stfc.ac.uk/.well-known/openid-configuration).
That document lists supported scopes (`openid`, `profile`, `email`, …) and claims
including `preferred_username`, which this guide maps to `posix.username`.

This example uses:

- Keycloak realm: `master`
- Identity provider alias: `SKAIAM`
- Local Keycloak URL: `http://localhost:8080`

Adjust hostnames, realm, and alias for your environment.

---

## Part 1 — SKA IAM client registration

1. Sign in to the SKA IAM administration console for your deployment.
2. Create a new **OIDC client** for Keycloak (name is arbitrary, e.g. `keycloak-local`).
3. Set the **redirect URI** to the Keycloak broker callback for your realm and IdP alias:

   ```
   http://localhost:8080/realms/master/broker/SKAIAM/endpoint
   ```

   If you use a different realm or alias, replace `master` and `SKAIAM` accordingly.
   Keycloak shows the exact redirect URI under **Identity providers → SKAIAM → Settings**
   after the provider is created.

4. Enable at least these **scopes** on the client:

   - `openid`
   - `profile`
   - `email`

   The `profile` scope is required for the `preferred_username` claim. Without it,
   Keycloak receives `sub` but not `preferred_username`, and POSIX provisioning
   falls back to the default `{uid}` username template.

5. Note the **client ID** and **client secret** issued by SKA IAM. You will enter
   these when configuring the OIDC identity provider in Keycloak.

---

## Part 2 — Keycloak

### 2.1 Build and start the customized image

From the repository root:

```bash
cd cadc-access-control-keycloak
../gradlew clean build checkstyleMain
docker build -t keycloak-opencadc-posix .
docker run --name keycloak-opencadc-posix \
  -p 8080:8080 \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin \
  -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
  keycloak-opencadc-posix start-dev
```

Open the Admin Console at [http://localhost:8080](http://localhost:8080) and sign
in with the bootstrap admin credentials.

### 2.2 Enable Unmanaged Attributes

POSIX attributes are stored as custom user attributes (`posix.username`, etc.).

1. Select the target realm (`master` in this example).
2. Go to **Realm settings → General**.
3. Set **Unmanaged Attributes** to **Enabled** (or **Admin can edit**,
   depending on your Keycloak version).
4. Save.

### 2.3 Enable the POSIX event listener

1. Go to **Realm settings → Events**.
2. Under **Event listeners**, add **opencadc-posix**.
3. Save.

See the main [README](../README.md) for optional `keycloak.properties` tuning of UID
ranges and home-directory templates.

### 2.4 Add SKAIAM as an OIDC identity provider

1. Go to **Identity providers → Add provider → OpenID Connect v1.0**.
2. Set **Alias** to `SKAIAM` (must match the redirect URI registered in SKA IAM).
3. Set **Discovery endpoint** to:

   ```
   https://ska-iam.stfc.ac.uk/.well-known/openid-configuration
   ```

4. Enter the **Client ID** and **Client secret** from Part 1.
5. Leave **Disable user info** off so Keycloak can read claims from the UserInfo
   endpoint if they are not present in the ID token.
6. Save.

### 2.5 Set default scopes

1. Open **Identity providers → SKAIAM → Settings**.
2. Expand **Advanced settings** (or **General settings**, depending on version).
3. Set **Scopes** to:

   ```
   openid profile email
   ```

4. Save.

### 2.6 Map `preferred_username` to `posix.username`

1. Open **Identity providers → SKAIAM → Mappers**.
2. Click **Add mapper → Attribute Importer**.
3. Configure:

   | Field | Value |
   |-------|--------|
   | Name | `posix-username-from-preferred_username` |
   | Sync mode override | `import` (or `force` to always refresh from the IdP) |
   | Claim | `preferred_username` |
   | User Attribute Name | `posix.username` |

4. Save.

When a user first logs in via SKA IAM, Keycloak stores the IdP `preferred_username`
as `posix.username`. The **opencadc-posix** listener then uses that value when
allocating UID, home directory, and related POSIX attributes.

---

## Part 3 — Verify

1. Open an incognito browser window.
2. Go to **Identity providers → SKAIAM** and click **Open connection** (or use a
   client application configured against Keycloak).
3. Authenticate via SKA IAM.
4. In the Admin Console, open **Users**, select the new user, and check **Attributes**:
   - `posix.username` should match the SKA IAM `preferred_username`.
   - `posix.uidNumber`, `posix.homeDirectory`, and other POSIX attributes should
     be populated by the event listener.

If `posix.username` is missing but `sub` works when mapped instead, confirm that
`profile` is included in the IdP **Scopes** and that the SKA IAM client allows
that scope.

---

## Reference

| Item | Value |
|------|--------|
| SKA IAM issuer | `https://ska-iam.stfc.ac.uk/` |
| OIDC discovery | `https://ska-iam.stfc.ac.uk/.well-known/openid-configuration` |
| Keycloak redirect URI (this example) | `http://localhost:8080/realms/master/broker/SKAIAM/endpoint` |
| Required scopes | `openid profile email` |
| Claim → attribute | `preferred_username` → `posix.username` |

To map stored POSIX attributes into outbound JWT access tokens for internal services,
see [POSIX token claims](POSIX-Token-Claims.md).
