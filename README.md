# CentralAuth Desktop App Demo (Rust)

This is a small Rust demo that shows how to use CentralAuth in a desktop app flow. It opens a browser for login, runs a local loopback server on `http://localhost:12120` to capture the OAuth redirect, and then calls your backend to fetch the user profile.

## What it does

- Creates a device identifier and fetches a nonce from CentralAuth
- Builds a client-assertion JWT
- Launches the CentralAuth login page in the default browser
- Receives the authorization code via a loopback redirect
- Exchanges the code for an access token
- Calls your backend (`/api/auth/user`) and prints the logged-in email

## Prerequisites

- Rust (2024 edition)
- A CentralAuth app with `APP_ID` and `CLIENT_ID`
- A backend that exposes `/api/auth/user` and accepts a bearer token

## Configuration

This demo uses compile-time environment variables. Configure them in a `.cargo/config.toml` file in the project root.

Required:

- `APP_ID` - The CentralAuth app id
- `CLIENT_ID` - The CentralAuth client id

Optional:

- `BASE_URL` - Your backend base URL (default: `http://localhost:3000`)
- `AUTH_BASE_URL` - CentralAuth base URL (default: `https://centralauth.com`)

Create a `.cargo/config.toml` file in the project root with your settings:

```toml
[env]
APP_ID = "your-app-id"
CLIENT_ID = "your-client-id"
BASE_URL = "http://localhost:3000"
AUTH_BASE_URL = "https://centralauth.com"
```

**Note:** Add `.cargo/config.toml` to your `.gitignore` to avoid committing sensitive credentials

## Run

```bash
cargo run
```

The app will open a browser window for login. After you finish, the console will print the access token and the email from your backend.

## Notes on client assertion

- This demo signs a client-assertion JWT using a value derived from the app signing certificate on Windows and macOS.
- On macOS, it reads the app's code-signing certificate (leaf cert) via the Security framework and computes the SHA-256 thumbprint from the DER-encoded certificate.
- On non-Windows/macOS platforms, certificate retrieval is not generally supported. The demo uses a placeholder value for the client assertion, which will not work in production. You will need to implement your own method of generating a client assertion based on your app's signing certificate or another secure method.
- Do not embed private keys in source code in real apps.

## Troubleshooting

- If the browser does not open, copy the printed URL into your browser manually.
- Ensure nothing else is bound to `127.0.0.1:12120`.
- Verify that your backend accepts the access token and the `device-id` header.

## License

This demo is provided as-is for evaluation purposes.
