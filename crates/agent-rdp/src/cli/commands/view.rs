//! View command implementation - opens the web viewer served by the daemon.

use crate::cli::ViewArgs;
use crate::error::CliError;
use crate::output::Output;
use agent_rdp_daemon::stream_auth::stream_url;
use agent_rdp_protocol::ErrorCode;

pub async fn run(args: ViewArgs, output: &Output) -> anyhow::Result<()> {
    // The daemon serves the viewer HTML on the same port as the WebSocket server
    // The stream requires its token, so the viewer URL carries it
    let url = view_url(args.port, args.token.as_deref());

    if !output.is_json() {
        println!("Opening viewer at: {}", url);
    }

    // With --json, print the URL only once the browser opened, so a failure prints one document
    open::that(&url).map_err(|e| {
        CliError::new(
            ErrorCode::InternalError,
            format!("Failed to open browser at {url}: {e}"),
        )
    })?;

    if output.is_json() {
        println!("{}", serde_json::json!({ "url": url }));
    }

    Ok(())
}

/// The viewer URL for a stream port, with the stream token when one is given.
fn view_url(port: u16, token: Option<&str>) -> String {
    match token {
        Some(token) => stream_url("http", "localhost", port, token),
        None => format!("http://localhost:{}", port),
    }
}

#[cfg(test)]
mod tests {
    use super::view_url;

    #[test]
    fn view_url_carries_the_token_when_given() {
        assert_eq!(
            view_url(9224, Some("abc")),
            "http://localhost:9224/?token=abc"
        );
        assert_eq!(view_url(9224, None), "http://localhost:9224");
    }
}
