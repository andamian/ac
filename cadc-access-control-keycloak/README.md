# Keycloak POSIX Account Extension

Keycloak 26.6.4 provider extension that auto-generates POSIX account details when a new
user account is created. Supports both the Keycloak internal database and writable LDAP
user federation.

## Features

- Assigns `uidNumber`, `gidNumber`, `homeDirectory`, `loginShell`, and `posix.username` on user creation
- LDAP backend via `opencadc-posix-account` LDAP mapper
- Keycloak DB backend via `opencadc-posix` event listener
- Skips users that already have POSIX attributes
- Random UID allocation within a configurable range
- Optional OIDC issuer-based username prefixes for external IdP accounts (collision avoidance)
- VOSI `/capabilities` and POSIX user-mapping `/uid` lookup REST endpoints

## User attributes

| Keycloak attribute | LDAP attribute | Default |
|--------------------|--------------|---------|
| `posix.username` | `uid` | `{uid}` (numeric UID as string) |
| `posix.uidNumber` | `uidNumber` | allocated UID |
| `posix.gidNumber` | `gidNumber` | same as UID |
| `posix.homeDirectory` | `homeDirectory` | `{usersHome}/{username}` → `/home/{uid}` |
| `posix.loginShell` | `loginShell` | `/bin/nologin` |

`posix.username` may be set before provisioning runs — for example via an Identity Provider
attribute mapper (external claim) or a user profile / registration field. When absent, the
configured username template is applied (default `{uid}`).

For a full walkthrough using the [SKA IAM prototype](https://ska-iam.stfc.ac.uk/) INDIGO
IAM IdP, see [INDIGO IAM (SKA IAM) setup](docs/INDIGO-IAM-SKAIAM-Setup.md).

For admin-console user creation — using the **Username** field as `posix.username`
with format and duplicate-name validation — see [Admin user creation](docs/Admin-User-Creation.md).
Invalid admin usernames are rejected in the Admin Console before the account is created.

To expose POSIX attributes as claims in OIDC access tokens for internal services, see
[POSIX token claims](docs/POSIX-Token-Claims.md).

To obtain a service token for `/uid` lookup (client credentials grant), see
[Service token](docs/Service-Token.md).

## Building

Requires Java 17 to compile and test. The Gradle wrapper runs on Java 11, but this module
forks a Java 17 compiler and test runtime. Set `JDK17_HOME` if OpenJDK 17 is installed in a
non-default location.

```bash
cd cadc-access-control-keycloak
../gradlew clean build checkstyleMain
```

## Deployment

Build the extension, then build a Keycloak image with the provider JAR installed:

```bash
cd cadc-access-control-keycloak
../gradlew clean build checkstyleMain
docker build -t keycloak-opencadc-posix .
```

### UMS deployment

The UMS is served under the HTTP relative path **`/ums`**. VOSI capabilities are exposed at the
flat public path **`/ums/capabilities`** via a Quarkus reactive route inside the extension.
The authenticated `/uid` lookup stays on the native Keycloak realm resource path; the
capabilities document advertises that URL to clients such as `PosixMapperClient`.

Configuration is supplied at **start time**, not baked into the Docker image. A sample file
is in [`src/test/resources/keycloak.properties`](src/test/resources/keycloak.properties).
Copy it, edit values for your environment, and provide it to Keycloak at runtime.

This project names the sample **`keycloak.properties`** for consistency with other OpenCADC
services, but Keycloak only loads SPI settings from **`.conf`** files. At runtime, mount or
copy the file as `keycloak.conf`. Also use the **full SPI property names** from the sample
(not `public-base-url` alone).

| Setting | Purpose |
|---------|---------|
| `http-relative-path=/ums` | Application root for OIDC, admin, and UMS |
| `spi-realm-restapi-extension-posix-public-base-url` | Base URL in VOSI capabilities |
| `spi-realm-restapi-extension-posix-realm` | Realm for derived `/uid` accessURL |
| `spi-realm-restapi-extension-posix-uid-access-url` | Optional override for `/uid` in capabilities |

The extension does **not** require any particular port. Keycloak listens on **8080** inside
the container by default. Set `spi-realm-restapi-extension-posix-public-base-url` to
the URL clients actually use (scheme, host, port, and `/ums` prefix).

The `/uid` access URL in the capabilities XML defaults to
`{public-base-url}/realms/{realm}/posix/uid`.

Public URLs (with `http-relative-path=/ums`, default realm `master`):

| Public URL | Served by | Auth |
|------------|-----------|------|
| `/ums/capabilities` | Quarkus route in extension | none |
| `/ums/realms/{realm}/posix/uid` | Keycloak realm resource | Bearer token |
| `/ums/realms/{realm}/protocol/openid-connect/…` | Keycloak | varies |
| `/ums/admin/…` | Keycloak admin | admin |

Run locally:

```bash
cd cadc-access-control-keycloak
../gradlew clean build checkstyleMain
docker build -t keycloak-opencadc-posix .

cp src/test/resources/keycloak.properties /tmp/keycloak.conf

docker run --name keycloak-opencadc-posix \
  -p 8080:8080 \
  -v /tmp/keycloak.conf:/opt/keycloak/conf/keycloak.conf:ro \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin \
  -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
  keycloak-opencadc-posix start-dev
```

Or pass an explicit config file (`--config-file` must come **before** `start-dev`):

```bash
docker run --name keycloak-opencadc-posix \
  -p 8080:8080 \
  -v /tmp/keycloak.conf:/config/keycloak.conf:ro \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin \
  -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
  keycloak-opencadc-posix --config-file=/config/keycloak.conf start-dev
```

Example:

```bash
curl http://localhost:8080/ums/capabilities
```

See [Service token](docs/Service-Token.md) for obtaining a bearer token and calling `/uid`.

Settings in the sample file can also be supplied as environment variables (for example
`KC_HTTP_RELATIVE_PATH=/ums`,
`KC_SPI_REALM_RESTAPI_EXTENSION_POSIX_PUBLIC_BASE_URL=…`). Environment variables
override the file.

Optional POSIX provisioning settings (see sample file comments) and realm admin-console
steps for LDAP mappers and the `opencadc-posix` event listener are documented below.

For production, set `hostname`, enable TLS, update `public-base-url` to the public
`https://…/ums` URL, and use `start` instead of `start-dev` with a database.

The image is based on `quay.io/keycloak/keycloak:26.6.4`, copies the built JAR into
`/opt/keycloak/providers/`, and runs `kc.sh build` so Keycloak registers the extension at
image build time.

Manual install into an existing Keycloak installation:

```bash
cp build/libs/cadc-access-control-keycloak-*.jar /opt/keycloak/providers/
/opt/keycloak/bin/kc.sh build
/opt/keycloak/bin/kc.sh start-dev --config-file=/path/to/keycloak.properties
```

### LDAP realm configuration

1. Configure a writable LDAP user federation provider.
2. Open the provider **Mappers** tab.
3. Add mapper type **opencadc-posix-account**.
4. Configure the UID range and home directory template as needed.

The LDAP provider must allow Keycloak to create users (`Edit Mode: WRITABLE`). The user
entry should support the `posixAccount` object class.

### Keycloak database realm configuration

1. Open **Realm settings → Events**.
2. Enable the **opencadc-posix** event listener.

Optional listener settings in `keycloak.conf`:

```properties
spi-events-listener--opencadc-posix--enabled=true
spi-events-listener--opencadc-posix--posix-uid-min=10000
spi-events-listener--opencadc-posix--posix-uid-max=2000000000
spi-events-listener--opencadc-posix--posix-users-home=/home
spi-events-listener--opencadc-posix--posix-username-template={uid}
spi-events-listener--opencadc-posix--posix-home-template={usersHome}/{username}
spi-events-listener--opencadc-posix--posix-login-shell=/bin/nologin
# Optional OIDC issuer -> username prefix pairs (comma-separated iss:prefix)
# The final colon in each pair separates issuer URL from prefix.
spi-events-listener--opencadc-posix--posix-username-iss-prefixes=https://ska-iam.stfc.ac.uk/:ska
```

Keycloak SPI property names use **dashes** in `keycloak.conf`, not dots. For example,
`posix.username.iss-prefixes` in code maps to
`spi-events-listener--opencadc-posix--posix-username-iss-prefixes` in the file.
The double dash (`--`) between SPI segments is Keycloak's standard format; a
single-dash form such as
`spi-events-listener-opencadc-posix-posix-username-iss-prefixes` is also accepted.

When issuer-prefix pairs are configured, external IdP first-login provisioning maps
the IdP `preferred_username` to `{prefix}-{preferred_username}` for both the Keycloak
username and `posix.username` (for example `user` → `ska-user`). Usernames matching
`{prefix}-*` are reserved for IdP-provisioned accounts; local admin, registration,
and SCIM flows cannot claim them. Prefixing applies only on first IdP login; existing
accounts are not renamed retroactively.

Template placeholders:

| Placeholder | Meaning |
|-------------|---------|
| `{usersHome}` | Value of `posix.users.home` (default `/home`) |
| `{username}` | Resolved `posix.username` |
| `{uid}` | Allocated numeric UID |
| `{keycloakUsername}` | Keycloak login username |

## UMS REST endpoints

The extension exposes VOSI capabilities and POSIX user-mapping lookup:

| Path | Auth | Description |
|------|------|-------------|
| `/ums/capabilities` | none | VOSI capabilities (flat public path via Quarkus route) |
| `/ums/realms/{realm}/posix/capabilities` | none | Same capabilities document (realm resource alias) |
| `/ums/realms/{realm}/posix/uid` | Bearer token | POSIX user mapping lookup |

With `http-relative-path=/ums`, all paths above are prefixed with `/ums`. The capabilities
document advertises the flat `/capabilities` URL and the realm-scoped `/uid` URL.

### `/uid` lookup

Read-only lookup of existing POSIX mappings. No provisioning is performed; missing users
return HTTP 404.

Obtain a service token with the [client credentials grant](docs/Service-Token.md), then:

```bash
curl -H "Authorization: Bearer $TOKEN" \
  -H "Accept: text/tab-separated-values" \
  "http://localhost:8080/ums/realms/master/posix/uid?user=jsmith"
```

Query parameters:

| Parameter | Meaning |
|-----------|---------|
| `user` | Lookup by `posix.username` or Keycloak login username |
| `uid` | Lookup by `posix.uidNumber` |
| (none) | Stream all users with POSIX attributes |

TSV response format (one mapping per line):

```
username\tuid\tdefaultGroup
```

## Scope

This extension provisions POSIX details for newly created Keycloak users and exposes
read-only POSIX user-mapping lookup via `/uid`. Migration from the legacy `ac` service or
`posix-mapper` is out of scope. Group GID mapping (`/gid`) belongs in a separate service.
