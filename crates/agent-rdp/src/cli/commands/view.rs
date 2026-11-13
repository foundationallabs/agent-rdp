//! View command implementation - opens the web viewer served by the daemon.

use crate::cli::ViewArgs;
use crate::output::Output;
use agent_rdp_daemon::stream_auth::stream_url;

pub async fn run(args: ViewArgs, output: &Output) -> anyhow::Result<()> {
    // The daemon serves the viewer HTML on the same port as the WebSocket server
    // The stream requires its token, so the viewer URL carries it
    let url = view_url(args.port, args.token.as_deref());

    if output.is_json() {
        println!(r#"{{"url":"{}"}}"#, url);
    } else {
        println!("Opening viewer at: {}", url);
    }

    // Open browser
    if let Err(e) = open::that(&url) {
        output.print_error("open_failed", &format!("Failed to open browser: {}", e));
        std::process::exit(1);
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
        assert_eq!(view_url(9224, Some("abc")), "http://localhost:9224/?token=abc");
        assert_eq!(view_url(9224, None), "http://localhost:9224");
    }
}
