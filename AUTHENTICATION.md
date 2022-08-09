# Authentication

- `POST` `application/json` or `application/x-www-form-urlencoded` endcoded `email` to `/api/v1/login/request-magic`. Response will always be `200` if properly formatted with empty payload.
- If `email` adress exists, an email is sent to that address with a link to `/magic-login?token=<token>`
- `GET` `/magic-login?token=<token>` will set session cookie and return HTML message. At present no redirect happens.

## Chrome Extension

- `POST` JSON encoded `token` to `/api/v1/login/use-magic` returns `accessToken` + `expiresIn`, `emailAccount` (email address) and the `trackingSlug`.
- The `userId` can be obtained from the `accessToken` by decoding it as a JWT and reading off the `sub`
- Extension redirects browser window to `/logged-in` and attempts to close the window.
- `GET` `/logged-in` returns HTML page with: `"You are logged in. You may close this window."`

## Gmail Addon

- `GET` `/o/oauth2/auth`, if not logged in renders HTML form with button to `POST` `/api/v1/login/request-magic`. Recieves the desired email in `login_hint` query param.
- If logged in already, performs oauth2 authorize.
- `authorization_code` flow is used where the authorization code is a short lived JWT. No revocation, etc happens right now.
