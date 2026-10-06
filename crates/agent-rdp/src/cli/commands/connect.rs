//! Connect command implementation.

use std::io::{self, BufRead};
use std::path::Path;

use agent_rdp_protocol::{ConnectRequest, DriveMapping, Request};

use crate::cli::ConnectArgs;
use crate::output::Output;
use crate::session_manager::SessionManager;

pub async fn run(
    session: &str,
    args: ConnectArgs,
    output: &Output,
    timeout_ms: u64,
    stream_port: u16,
) -> anyhow::Result<()> {
    // Get password from args, env, or stdin
    let password = get_password(&args, output)?;

    // Parse drive mappings
    let drives = parse_drive_mappings(&args.drives, output)?;

    let manager = SessionManager::new(session.to_string());
    let mut client = manager.ensure_daemon().await?;

    let request = Request::Connect(build_connect_request(args, password, drives, stream_port));

    let response = client.send(&request, timeout_ms).await?;
    output.print_response(&response);

    if !response.success {
        std::process::exit(1);
    }

    Ok(())
}

/// Map parsed CLI arguments onto the connect request sent to the daemon.
fn build_connect_request(
    args: ConnectArgs,
    password: String,
    drives: Vec<DriveMapping>,
    stream_port: u16,
) -> ConnectRequest {
    ConnectRequest {
        host: args.host,
        port: args.port,
        username: args.username,
        password,
        domain: args.domain,
        alternate_shell: args.alternate_shell,
        width: args.width,
        height: args.height,
        drives,
        enable_win_automation: args.enable_win_automation,
        stream_port,
        // CLI enables the viewer HTML when streaming is enabled
        serve_viewer: stream_port > 0,
        ..Default::default()
    }
}

/// Parse drive mapping strings (format: /path:DriveName) into DriveMappings.
fn parse_drive_mappings(drives: &[String], output: &Output) -> anyhow::Result<Vec<DriveMapping>> {
    let mut result = Vec::new();

    for drive_spec in drives {
        // Find the last colon to split path from name
        if let Some(colon_pos) = drive_spec.rfind(':') {
            let path = &drive_spec[..colon_pos];
            let name = &drive_spec[colon_pos + 1..];

            if path.is_empty() {
                output.print_error(
                    "invalid_drive",
                    &format!("Invalid drive mapping '{}': path cannot be empty", drive_spec),
                );
                std::process::exit(1);
            }

            if name.is_empty() {
                output.print_error(
                    "invalid_drive",
                    &format!("Invalid drive mapping '{}': name cannot be empty", drive_spec),
                );
                std::process::exit(1);
            }

            // Expand ~ to home directory and verify path exists
            let expanded_path = shellexpand::tilde(path);
            let path_ref = Path::new(expanded_path.as_ref());

            if !path_ref.exists() {
                output.print_error(
                    "invalid_drive",
                    &format!("Drive path '{}' does not exist", expanded_path),
                );
                std::process::exit(1);
            }

            if !path_ref.is_dir() {
                output.print_error(
                    "invalid_drive",
                    &format!("Drive path '{}' is not a directory", expanded_path),
                );
                std::process::exit(1);
            }

            result.push(DriveMapping {
                path: expanded_path.into_owned(),
                name: name.to_string(),
            });
        } else {
            output.print_error(
                "invalid_drive",
                &format!(
                    "Invalid drive mapping '{}': expected format /path:DriveName",
                    drive_spec
                ),
            );
            std::process::exit(1);
        }
    }

    Ok(result)
}

/// Get password from command line, environment, or stdin.
fn get_password(args: &ConnectArgs, output: &Output) -> anyhow::Result<String> {
    // Priority: --password-stdin > --password/env
    if args.password_stdin {
        let stdin = io::stdin();
        let mut line = String::new();
        stdin.lock().read_line(&mut line)?;
        return Ok(line.trim_end().to_string());
    }

    if let Some(ref password) = args.password {
        return Ok(password.clone());
    }

    // No password provided
    output.print_error(
        "missing_password",
        "Password required. Use --password, AGENT_RDP_PASSWORD env var, or --password-stdin",
    );
    std::process::exit(1);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{Cli, Commands};
    use clap::Parser;

    const PSM_SHELL: &str = "psm /u a@b /a host /c PSM-RDP";

    fn parse_connect(extra: &[&str]) -> ConnectArgs {
        let mut argv = vec!["agent-rdp", "connect", "--host", "h", "-u", "user"];
        argv.extend_from_slice(extra);
        match Cli::try_parse_from(argv).expect("args parse").command {
            Commands::Connect(args) => args,
            _ => panic!("expected connect command"),
        }
    }

    fn request_for(extra: &[&str]) -> ConnectRequest {
        build_connect_request(parse_connect(extra), "pw".to_string(), Vec::new(), 0)
    }

    #[test]
    fn alternate_shell_flag_round_trips_verbatim() {
        let request = request_for(&["--alternate-shell", PSM_SHELL]);
        assert_eq!(request.alternate_shell.as_deref(), Some(PSM_SHELL));
    }

    #[test]
    fn alternate_shell_flag_equals_form_round_trips_verbatim() {
        let flag = format!("--alternate-shell={PSM_SHELL}");
        let request = request_for(&[flag.as_str()]);
        assert_eq!(request.alternate_shell.as_deref(), Some(PSM_SHELL));
    }

    // Env-dependent cases live in one test: parallel tests must not race on the process env.
    #[test]
    fn alternate_shell_absent_flag_is_none_and_env_is_the_fallback() {
        const VAR: &str = "AGENT_RDP_ALTERNATE_SHELL";
        std::env::remove_var(VAR);
        assert_eq!(request_for(&[]).alternate_shell, None);

        std::env::set_var(VAR, PSM_SHELL);
        let from_env = request_for(&[]).alternate_shell;
        let from_flag = request_for(&["--alternate-shell", "other shell"]).alternate_shell;
        std::env::remove_var(VAR);

        assert_eq!(from_env.as_deref(), Some(PSM_SHELL));
        assert_eq!(from_flag.as_deref(), Some("other shell"));
    }

    #[test]
    fn connect_request_carries_other_cli_fields() {
        let request = build_connect_request(
            parse_connect(&["--port", "4489", "-d", "CORP", "--width", "1920", "--height", "1080"]),
            "pw".to_string(),
            vec![DriveMapping {
                path: "/tmp/x".to_string(),
                name: "X".to_string(),
            }],
            9224,
        );
        assert_eq!(request.host, "h");
        assert_eq!(request.port, 4489);
        assert_eq!(request.username, "user");
        assert_eq!(request.password, "pw");
        assert_eq!(request.domain.as_deref(), Some("CORP"));
        assert_eq!((request.width, request.height), (1920, 1080));
        assert_eq!(request.drives.len(), 1);
        assert_eq!(request.stream_port, 9224);
        assert!(request.serve_viewer);
    }
}
