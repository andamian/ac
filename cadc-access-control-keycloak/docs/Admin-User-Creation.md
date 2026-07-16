# Admin console user creation and POSIX username

When an administrator creates a user in the Keycloak Admin Console, the required
**Username** field becomes `posix.username` when it is valid and not already taken.
Invalid or duplicate usernames are rejected before the account is created.

## Username format

POSIX usernames must match `^[A-Za-z0-9_-]+$` — letters, digits, underscore,
and hyphen only, with no whitespace or other punctuation.

## Resolution order

When POSIX details are provisioned, `posix.username` is resolved as follows:

1. Existing `posix.username` attribute (for example from an IdP mapper), when valid
2. Keycloak **username**, when it matches the POSIX username format
3. Configured username template (default `{uid}`) — used for self-registration only;
   admin-created users must supply a valid username in step 2

## Validation

The extension automatically attaches two validators to the **username** attribute
when a username is first chosen via the Admin Console, self-registration, or SCIM
(Identity Provider first-login review and login-time profile verification are excluded):

| Validator ID | Purpose |
|--------------|---------|
| `opencadc-posix-username-format` | Letters, digits, underscore, hyphen; no whitespace |
| `opencadc-posix-username-unique` | Not already used as `posix.username` |

No manual User Profile JSON editing is required. The extension registers
`PosixUserProfileProviderFactory`, which extends Keycloak's declarative user
profile provider and adds these validators automatically.

If validation is bypassed (for example via a direct Admin REST API call), the
`opencadc-posix` event listener rejects admin user creation when the username is
invalid or already assigned as `posix.username`, causing the transaction to roll
back.

### Error messages

| Message key | Meaning |
|-------------|---------|
| `posix-username-invalid` | Username contains invalid characters or whitespace |
| `posix-username-in-use` | Username is already assigned as `posix.username` |

Default English messages are bundled with the extension. To customize the text
shown in the Admin Console, add realm message bundle entries, for example:

```properties
posix-username-invalid=Username must contain only letters, digits, underscore, and hyphen (no spaces or other symbols).
posix-username-in-use=POSIX username already in use. Choose a different username.
```

### Optional manual configuration

If you maintain a custom User Profile JSON, you may add the validators explicitly
on the `username` attribute. This is optional when the extension is deployed:

```json
"opencadc-posix-username-format": {},
"opencadc-posix-username-unique": {}
```

## Example

| Admin enters username | Existing `posix.username` | Result |
|-----------------------|-------------------------|--------|
| `jsmith` | none | User created; `posix.username=jsmith` |
| `test_admin_user` | none | User created; `posix.username=test_admin_user` |
| `jsmith` | already on another user | validation error in Admin Console |
| `j.smith` | none | validation error (`posix-username-invalid`) |
| `alice smith` | none | validation error (`posix-username-invalid`) |
| `j.smith@example.com` | none | validation error (`posix-username-invalid`) |

## Related configuration

See the main [README](../README.md) for POSIX listener settings and the
[INDIGO IAM setup guide](INDIGO-IAM-SKAIAM-Setup.md) for IdP-provisioned
`posix.username` values.
