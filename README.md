# keycloak-email-lookup-or-create

Two small, composable Keycloak authenticators for building **passwordless,
login-or-signup** browser flows — one email form that signs in existing users
and creates new ones, with no separate registration step.

The library is **verification-agnostic**: it provides the "identify or create the
user" piece and leaves *proving* ownership to whatever step you put next (an
email or SMS one-time code, a magic link, etc.). It sends nothing itself.

Built and tested against **Keycloak 26.5** (`keycloak.version` in `pom.xml`).

## What it provides

| Provider id | `requiresUser()` | What it does |
|---|---|---|
| `email-lookup-or-create` | `false` | Renders the email form, looks the user up by email (falls back to username), and **creates one if none exists** (username = email, unverified), then sets it on the flow. |
| `set-email-verified` | `true` | Sets the authenticated user's `emailVerified = true`. Optional; place it **after** your verification step, so reaching it is the proof of ownership. No-op if already verified or no user. |

## Why

Keycloak's built-in username/email forms reject unknown users, so onboarding new
users normally means a separate registration flow. Passwordless products usually
want the opposite: a single form where existing and new users are
indistinguishable — enter email → prove ownership → you're in. This library
supplies the missing "find-or-create the user" step so you can assemble that flow
from a verification authenticator of your choice.

## Example flow

```
Cookie | Identity Provider Redirector | forms (subflow):
   email-lookup-or-create        (REQUIRED)   ← enter email; find or create the user
   <your ownership check: email/SMS code, magic link, …>  (REQUIRED)   ← prove ownership
   set-email-verified            (REQUIRED)   ← optional: mark email verified
```

- Known and unknown emails take the **same path**, so the form doesn't reveal
  which addresses are registered (no account enumeration).
- A new user is created **unverified** with `username = email`; `set-email-verified`
  flips the flag only after your verifier confirms ownership (so an abandoned
  attempt never leaves a falsely-verified account).

## Build

No local JDK/Maven required — build in Docker:

```bash
docker compose run --rm build
# -> target/keycloak-email-lookup-or-create.jar  (unit tests run first)
```

Or with Maven directly: `mvn clean package`.

## Install

Copy `target/keycloak-email-lookup-or-create.jar` into Keycloak's
`/opt/keycloak/providers/` (before `kc.sh build` for an optimized image, or the
providers dir + restart), then add the authenticators to a browser flow — via
the admin console (Authentication → Flows) or your infrastructure-as-code.

## Notes

- Make `firstName` / `lastName` **optional** in the realm's user profile if you
  want truly email-only signup; otherwise Keycloak's `VERIFY_PROFILE` required
  action interrupts the first login of a name-less user.
- `email-lookup-or-create` declares `requiresUser() = false` (it may create the
  user); it normalizes the email (trim + lowercase) and records the attempted
  username for downstream steps and events.

## Test

JUnit 5 + Mockito (`mvn test`, or the `docker compose` build above). Covers
create-on-unknown, reuse-existing, username fallback, email normalization,
invalid/empty-email rejection, and the verified-flag logic.

## Compatibility

The Keycloak Authenticator SPI can change across major versions. Bump
`keycloak.version` in `pom.xml` and rebuild when upgrading Keycloak.
