//!
//! This example showcases the Github OAuth2 process for requesting access to the user's public repos and
//! email address.
//!
//! Before running it, you'll need to generate your own Github OAuth2 credentials.
//!
//! In order to run the example call:
//!
//! ```sh
//! GITHUB_CLIENT_ID=xxx GITHUB_CLIENT_SECRET=yyy cargo run --example github
//! ```
//!
//! ...and follow the instructions.
//!

use oauth2::basic::BasicClient;
// Alternatively, this can be `oauth2::curl::http_client` or a custom client.
use oauth2::reqwest::async_http_client;
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, RedirectUrl, Scope,
    TokenResponse, TokenUrl,
};
use std::env;
use std::io::BufRead;
use url::Url;
use tide_querystring::ContextExt;
use std::collections::HashMap;

#[runtime::main]
async fn main() {
    let github_client_id = ClientId::new(
        env::var("GITHUB_CLIENT_ID").expect("Missing the GITHUB_CLIENT_ID environment variable."),
    );
    let github_client_secret = ClientSecret::new(
        env::var("GITHUB_CLIENT_SECRET")
            .expect("Missing the GITHUB_CLIENT_SECRET environment variable."),
    );
    let auth_url = AuthUrl::new(
        Url::parse("https://github.com/login/oauth/authorize")
            .expect("Invalid authorization endpoint URL"),
    );
    let token_url = TokenUrl::new(
        Url::parse("https://github.com/login/oauth/access_token")
            .expect("Invalid token endpoint URL"),
    );

    // Set up the config for the Github OAuth2 process.
    let client = BasicClient::new(
        github_client_id,
        Some(github_client_secret),
        auth_url,
        Some(token_url),
    )
    // This example will be running its own server at localhost:8080.
    // See below for the server implementation.
    .set_redirect_url(RedirectUrl::new(
        Url::parse("http://localhost:8080").expect("Invalid redirect URL"),
    ));

    // Generate the authorization URL to which we'll redirect the user.
    let (authorize_url, csrf_state) = client
        .authorize_url(CsrfToken::new_random)
        // This example is requesting access to the user's public repos and email.
        .add_scope(Scope::new("public_repo".to_string()))
        .add_scope(Scope::new("user:email".to_string()))
        .url();

    println!(
        "Open this URL in your browser:\n{}\n",
        authorize_url.to_string()
    );

    let mut app = tide::App::with_state(csrf_state);

    app.at("/").get(|cx: tide::Context<CsrfToken>| async move { 
        let query_param: HashMap<String, String> = cx.url_query().unwrap();

        let code: AuthorizationCode = query_param
            .get("code")
            .map(|c| AuthorizationCode::new(c.clone()))
            .unwrap();

        let state = query_param
            .get("state")
            .map(|s| CsrfToken::new(s.clone()))
            .unwrap();

        println!("Github returned the following code:\n{}\n", code.secret());
        println!(
            "Github returned the following state:\n{} (expected `{}`)\n",
            state.secret(),
            cx.state().secret()
        );

        "Go back to your terminal :)"
    });
    app.serve("127.0.0.1:8080").await;

    // TODO: figure out how to get the actual code here
    let code = AuthorizationCode::new("abc".to_string());

    // Exchange the code with a token.
    let token_res = client
        .exchange_code(code)
        .request_async(async_http_client)
        .await;

    println!("Github returned the following token:\n{:?}\n", token_res);

    if let Ok(token) = token_res {
        // NB: Github returns a single comma-separated "scope" parameter instead of multiple
        // space-separated scopes. Github-specific clients can parse this scope into
        // multiple scopes by splitting at the commas. Note that it's not safe for the
        // library to do this by default because RFC 6749 allows scopes to contain commas.
        let scopes = if let Some(scopes_vec) = token.scopes() {
            scopes_vec
                .iter()
                .map(|comma_separated| comma_separated.split(","))
                .flat_map(|inner_scopes| inner_scopes)
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        };
        println!("Github returned the following scopes:\n{:?}\n", scopes);
    }
}
