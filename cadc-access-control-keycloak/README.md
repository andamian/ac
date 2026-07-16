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

Run locally for development:

```bash
docker run --name keycloak-opencadc-posix \
  -p 8080:8080 \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin \
  -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
  keycloak-opencadc-posix start-dev
```

For production, use `start` instead of `start-dev` and configure a database, hostname, and TLS
as required by your environment.

The image is based on `quay.io/keycloak/keycloak:26.6.4`, copies the built JAR into
`/opt/keycloak/providers/`, and runs `kc.sh build` so Keycloak registers the extension at
image build time.

Manual install into an existing Keycloak installation:

```bash
cp build/libs/cadc-access-control-keycloak-*.jar /opt/keycloak/providers/
/opt/keycloak/bin/kc.sh build
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
spi-events-listener-opencadc-posix-posix.uid.min=10000
spi-events-listener-opencadc-posix-posix.uid.max=2000000000
spi-events-listener-opencadc-posix-posix.users.home=/home
spi-events-listener-opencadc-posix-posix.username.template={uid}
spi-events-listener-opencadc-posix-posix.home.template={usersHome}/{username}
spi-events-listener-opencadc-posix-posix.login.shell=/bin/nologin
```

Template placeholders:

| Placeholder | Meaning |
|-------------|---------|
| `{usersHome}` | Value of `posix.users.home` (default `/home`) |
| `{username}` | Resolved `posix.username` |
| `{uid}` | Allocated numeric UID |
| `{keycloakUsername}` | Keycloak login username |

## Scope

This extension provisions POSIX details for newly created Keycloak users only. Migration
from the legacy `ac` service or `posix-mapper` is out of scope.

In the longer term, POSIX lookup functionality currently provided by `posix-mapper` may be
served either by a thin proxy in front of Keycloak or by custom Keycloak REST endpoints
added to this extension.
