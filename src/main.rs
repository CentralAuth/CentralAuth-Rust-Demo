use oauth2::basic::BasicClient;
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, CsrfToken, PkceCodeChallenge, RedirectUrl, TokenUrl,
};
use oauth2::{TokenResponse, reqwest};
use serde::Serialize;
use url::Url;

use deviceid::DevDeviceId;
use std::env;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;

use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};

use chrono::{Duration, Utc};

mod signing_certificate;
#[cfg(any(target_os = "windows", target_os = "macos"))]
use signing_certificate::signing_certificate::get_signing_certificate;

#[derive(Serialize)]
struct Claims {
    iss: String,
    sub: String,
    aud: String,
    nonce: String,
    iat: usize,
    exp: usize,
}

fn get_thumbprint() -> String {
    #[cfg(any(target_os = "windows", target_os = "macos"))]
    {
        match get_signing_certificate() {
            Ok(cert) => {
                println!("Subject: {}", cert.subject);
                return cert.thumbprint_sha256;
            }
            Err(e) => {
                eprintln!("Certificate extraction failed: {}", e);
            }
        }
    }

    String::new()
}

fn main() {
    println!(
        "This demo app will walk you through the process of authenticating with CentralAuth using OAuth2. It will open your browser to the CentralAuth login page, and then exchange the authorization code for an access token. Finally, it will use the access token to fetch your user info from the API and display it.\n"
    );
    println!(
        "Note: This is a demonstration app. In a real application, you should handle errors gracefully, securely store the access token for future use and never print tokens and secrets in the console.\n"
    );

    // Set up the HTTP client we'll use to exchange data with CentralAuth.
    let http_client = reqwest::blocking::ClientBuilder::new()
        // Following redirects opens the client up to SSRF vulnerabilities.
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("Client should build");

    // Set up the data needed to start the OAuth2 process.
    println!("STEP 1: Set up the client configuration.\n");
    let app_id = env!("APP_ID");
    let device_id = DevDeviceId::get_or_generate().unwrap();
    let client_id: ClientId = ClientId::new(env!("CLIENT_ID").to_string());

    let base_url = option_env!("BASE_URL").unwrap_or("http://localhost:3000");
    let auth_base_url = option_env!("AUTH_BASE_URL").unwrap_or("https://centralauth.com");

    // Get a nonce from the server to include in the authorization URL. This is a security measure to prevent CSRF attacks.
    println!("STEP 2: Fetch a nonce from the server to include in the client challenge.\n");
    let mut client_challenge_url_builder = Url::parse(&auth_base_url).unwrap();
    client_challenge_url_builder.set_path(&format!(
        "/api/v1/client_challenge/{}",
        client_id.to_string()
    ));

    let nonce = http_client
        .get(client_challenge_url_builder.as_str())
        .send()
        .unwrap()
        .text()
        .unwrap();

    // Create a JWT client challenge token to include in the authorization URL.
    println!("STEP 3: Create a JWT client challenge token with the nonce.\n");
    let claims = Claims {
        iss: client_id.to_string(),
        sub: device_id.to_string(),
        aud: auth_base_url.to_owned(),
        nonce,
        iat: Utc::now().timestamp() as usize,
        exp: (Utc::now() + Duration::seconds(60)).timestamp() as usize,
    };

    //Get the thumbprint of the signing certificate to use as the secret for signing the JWT. The server will use this thumbprint to decode the JWT.
    println!(
        "STEP 4: Get the thumbprint of the signing certificate to use as the secret for signing the JWT.\n"
    );
    let thumbprint = get_thumbprint();

    // Sign the JWT using the private key. The server will verify the signature using the corresponding public key.
    // WARNING: In a real application, you should not include your private key in your source code (or commit it to version control). This is just for demonstration purposes.
    let client_assertion = encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(thumbprint.as_bytes()),
    )
    .expect("Failed to encode JWT");

    println!("Generated client assertion token:\n{}\n", client_assertion);

    // Set up the config for the CentralAuth OAuth2 process.
    println!("STEP 5: Set up the config for the CentralAuth OAuth2 process.\n");
    let mut auth_url_builder = Url::parse(&auth_base_url).unwrap();
    auth_url_builder.set_path("/login");
    auth_url_builder
        .query_pairs_mut()
        .append_pair("app_id", &app_id)
        .append_pair("device_id", &device_id.to_string())
        .append_pair("client_assertion", &client_assertion);
    let auth_url: AuthUrl =
        AuthUrl::new(auth_url_builder.to_string()).expect("Invalid authorization endpoint URL");

    let mut token_url_builder = Url::parse(&auth_base_url).unwrap();
    token_url_builder.set_path("/api/v1/verify");
    token_url_builder
        .query_pairs_mut()
        .append_pair("app_id", &app_id)
        .append_pair("device_id", &device_id.to_string());
    let token_url: TokenUrl =
        TokenUrl::new(token_url_builder.to_string()).expect("Invalid token endpoint URL");

    let client = BasicClient::new(client_id)
        .set_auth_uri(auth_url)
        .set_token_uri(token_url)
        // This example will be running its own server at localhost:12120.
        // See below for the server implementation.
        .set_redirect_uri(
            RedirectUrl::new("http://localhost:12120".to_string()).expect("Invalid redirect URL"),
        );

    // Create a PKCE code verifier and SHA-256 encode it as a code challenge.
    let (pkce_code_challenge, pkce_code_verifier) = PkceCodeChallenge::new_random_sha256();

    // Generate the authorization URL to which we'll redirect the user.
    let (authorize_url, csrf_state) = client
        .authorize_url(CsrfToken::new_random)
        .set_pkce_challenge(pkce_code_challenge)
        .url();

    println!(
        "STEP 6: Open the authorization URL in the user's browser and wait for the redirect with the authorization code.\n"
    );

    // Open the authorization URL in the user's browser.
    if let Err(err) = open::that(authorize_url.to_string()) {
        eprintln!(
            "Failed to open URL in browser. Please copy and paste the following URL into your browser:\n{}\n",
            authorize_url.to_string()
        );
        if cfg!(debug_assertions) {
            eprintln!("Open error: {}", err);
        }
    }

    println!(
        "STEP 7: Implement a local loopback server to receive the redirect and wait for the authorization code from CentralAuth.\n"
    );
    let (code, state) = {
        // Implement a local loopback server to receive the redirect with the authorization code from CentralAuth.
        let listener = TcpListener::bind("127.0.0.1:12120").unwrap();

        // The server will terminate itself after collecting the first code.
        let Some(mut stream) = listener.incoming().flatten().next() else {
            panic!("listener terminated without accepting a connection");
        };

        let mut reader = BufReader::new(&stream);

        let mut request_line = String::new();
        reader.read_line(&mut request_line).unwrap();

        let redirect_url = request_line.split_whitespace().nth(1).unwrap();
        let url = Url::parse(&(auth_base_url.to_owned() + redirect_url)).unwrap();

        // Extract the code and state from the URL query parameters.
        let code = url
            .query_pairs()
            .find(|(key, _)| key == "code")
            .map(|(_, code)| AuthorizationCode::new(code.into_owned()))
            .unwrap();

        let state = url
            .query_pairs()
            .find(|(key, _)| key == "state")
            .map(|(_, state)| CsrfToken::new(state.into_owned()))
            .unwrap();

        // Send a response to the browser.
        let message = "Please return to your app to continue.";
        let response = format!(
            "HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n{}",
            message.len(),
            message
        );
        stream.write_all(response.as_bytes()).unwrap();

        // Return the code and state.
        (code, state)
    };

    println!(
        "CentralAuth returned the following code:\n{}\n",
        code.secret()
    );
    println!(
        "CentralAuth returned the following state:\n{} (expected `{}`)\n",
        state.secret(),
        csrf_state.secret()
    );

    // Exchange the code with a token.
    println!("STEP 8: Exchange the authorization code for an access token.\n");
    let token_response = client
        .exchange_code(code)
        .set_pkce_verifier(pkce_code_verifier)
        .request(&http_client);

    // Fetch the user info from the API on the base URL using the token.
    let token_response = token_response.unwrap();
    let token = token_response.access_token().secret();

    println!("CentralAuth returned the following access token:\n{token:?}\n");

    println!("STEP 9: Use the access token to fetch the user info from the API.\n");
    let user_info_response = http_client
        .get(format!("{}/api/auth/user", base_url))
        .bearer_auth(token)
        .header("device-id", device_id.to_string())
        .send()
        .unwrap()
        .text()
        .unwrap();

    let user_info = json::parse(&user_info_response).unwrap();

    println!("Logged in as:\n{}\n", user_info["email"]);

    println!(
        "Demo complete! In a real application, you would now store the access token securely (e.g. in an encrypted file or secure vault) and use it to authenticate API requests on behalf of the user.\n"
    );

    #[cfg(target_os = "windows")]
    {
        println!("Press Enter to exit...");
        let _ = std::io::stdin().read_line(&mut String::new());
    }
}
