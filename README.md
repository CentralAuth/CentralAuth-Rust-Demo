# CentralAuth Desktop App Demo (Rust)

This is a small Rust demo that shows how to use CentralAuth in a desktop app flow. It opens a browser for login, runs a local loopback server on `http://localhost:12120` to capture the OAuth redirect, and then calls your backend to fetch the user profile.

## What it does

- Creates a device identifier and fetches a nonce from CentralAuth
- Builds a client-assertion JWT
- Launches the CentralAuth login page in the default browser
- Receives the authorization code via a loopback redirect
- Exchanges the code for an access token
- Calls your backend (`/api/auth/user`) and prints the logged-in email

In debug builds, the app also prints the generated client assertion and received access token for demo visibility.

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
- `API_KEY` - Only used in debug builds when fetching the nonce (sent as bearer token). Used to bypass the nonce check for easier local testing. Never include the API key in a production application or print it in the console! See the [API key section](https://docs.centralauth.com/admin/dashboard/organization/api-keys) in the CentralAuth docs for more details.

Create a `.cargo/config.toml` file in the project root with your settings:

```toml
[env]
APP_ID = "your-app-id"
CLIENT_ID = "your-client-id"
BASE_URL = "http://localhost:3000"
AUTH_BASE_URL = "https://centralauth.com"
API_KEY = "your-debug-api-key"
```

**Note:** Add `.cargo/config.toml` to your `.gitignore` to avoid committing sensitive credentials

## Run

```bash
cargo run
```

The app will open a browser window for login. After you finish, the console will print the access token and the email from your backend.

To build a release version:

```bash
cargo build --release
```

Note: release mode requires successful signing certificate extraction on supported platforms. On Windows, you can use the [SignTool](https://learn.microsoft.com/nl-nl/windows/win32/seccrypto/signtool) utility to sign the executable with your certificate. On macOS, you can use [`codesign`](https://developer.apple.com/documentation/xcode/creating-distribution-signed-code-for-the-mac) to sign the app bundle.

## Notes on client assertion

- In debug builds, the demo generates an unsigned JWT (`alg: none`) for the `client_assertion` to keep local testing simple.
- In release builds, the demo signs the JWT with `HS256` using the SHA-256 thumbprint of the app signing certificate.
- Windows: the thumbprint is extracted from the executable's embedded Authenticode signing certificate.
- macOS: the leaf signing certificate is extracted via `codesign --extract-certificates` and hashed.
- Linux/other platforms: signing certificate retrieval is not implemented, so release builds will fail at runtime unless you add your own production-safe signing approach.
- Never print or persist tokens/secrets in production apps.

## Troubleshooting

- If the browser does not open, copy the printed URL into your browser manually.
- Ensure nothing else is bound to `localhost:12120`.
- Verify that your backend accepts the access token and the `device-id` header.

## License

This demo is provided as-is for evaluation purposes.
