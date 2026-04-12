//! `mcpunit` binary entry point — clap-based CLI.
//!
//! The `test` subcommand drives one MCP discovery session and emits reports.
//! Exit codes:
//!
//! * `0` — test succeeded and the total score is at or above `--min-score`.
//! * `2` — test failed (transport error, invalid options, I/O failure).
//! * `3` — test succeeded but the total score is below `--min-score`.

use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, Write as _};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use clap::{Parser, Subcommand, ValueEnum};
use tracing_subscriber::{fmt, EnvFilter};

use mcpunit::error::TransportError;
use mcpunit::models::NormalizedServer;
use mcpunit::reporters::{
    JsonReporter, MarkdownReporter, Reporter, SarifReporter, TerminalReporter,
};
use mcpunit::scoring::{scan as scan_server, Report};
use mcpunit::transport::http::{HttpConfig, HttpTransport};
use mcpunit::transport::stdio::{StdioConfig, StdioTransport};
use mcpunit::transport::Transport;
use mcpunit::DEFAULT_MAX_RESPONSE_BYTES;

const EXIT_SUCCESS: u8 = 0;
const EXIT_TEST_FAILED: u8 = 2;
const EXIT_SCORE_BELOW_THRESHOLD: u8 = 3;

#[derive(Debug, Parser)]
#[command(
    name = "mcpunit",
    version,
    about = "Deterministic CI-first quality audit for MCP servers.",
    arg_required_else_help = true
)]
struct Cli {
    /// Logging verbosity filter (same syntax as `RUST_LOG`).
    #[arg(long, global = true, default_value = "info")]
    log: String,

    #[command(subcommand)]
    command: Option<Command>,

    /// Shorthand: `mcpunit ./server.js` is equivalent to
    /// `mcpunit test --cmd ./server.js`. Loads `.env` from the current
    /// directory automatically.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true, hide = true)]
    shorthand: Vec<String>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Test an MCP server and compute a deterministic quality score.
    Test(TestArgs),
}

#[derive(Debug, Clone, ValueEnum)]
enum TransportKind {
    Stdio,
    Http,
}

#[derive(Debug, Parser)]
struct TestArgs {
    /// Transport flavour. Defaults to `stdio` when `--cmd` is given and
    /// `http` when `--url` is given.
    #[arg(long, value_enum)]
    transport: Option<TransportKind>,

    /// Per-request timeout in seconds.
    #[arg(long, default_value_t = 10.0)]
    timeout: f64,

    /// Fail with exit code 3 when the total score is below this threshold
    /// (0..=100).
    #[arg(long, default_value_t = 0u32)]
    min_score: u32,

    /// Hard cap on a single JSON-RPC response / SSE event (bytes).
    #[arg(long, default_value_t = DEFAULT_MAX_RESPONSE_BYTES)]
    max_response_bytes: u64,

    /// Write the JSON report to this path.
    #[arg(long)]
    json_out: Option<PathBuf>,

    /// Write the SARIF report to this path.
    #[arg(long = "sarif-out")]
    sarif_out: Option<PathBuf>,

    /// Write the Markdown summary to this path.
    #[arg(long)]
    markdown_out: Option<PathBuf>,

    /// Streamable HTTP target URL (required with `--transport http`).
    #[arg(long, conflicts_with = "cmd")]
    url: Option<String>,

    /// Extra HTTP header as `Name: Value` — pass once per header.
    #[arg(long = "header", value_name = "NAME: VALUE")]
    headers: Vec<String>,

    /// Working directory for the subprocess.
    #[arg(long)]
    cwd: Option<PathBuf>,

    /// Extra environment variable for the subprocess as `KEY=VALUE`.
    /// Repeatable.
    #[arg(long = "env", value_name = "KEY=VALUE")]
    envs: Vec<String>,

    /// Path to a dotenv file to load into the subprocess environment.
    /// Defaults to `.env` in `--cwd` (or the current directory) when
    /// the file exists.
    #[arg(long)]
    dotenv: Option<PathBuf>,

    /// Subprocess to launch over stdio (everything after `--cmd` is
    /// captured as argv, so pass this flag last).
    #[arg(
        long,
        num_args = 1..,
        trailing_var_arg = true,
        allow_hyphen_values = true
    )]
    cmd: Option<Vec<String>>,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    init_tracing(&cli.log);

    // Shorthand: `mcpunit ./server.ts` → `mcpunit test --cmd npx tsx ./server.ts`
    let command = cli.command.or_else(|| {
        if cli.shorthand.is_empty() {
            None
        } else {
            let cmd = expand_shorthand(cli.shorthand);
            Some(Command::Test(TestArgs {
                transport: None,
                timeout: 10.0,
                min_score: 0,
                max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
                json_out: None,
                sarif_out: None,
                markdown_out: None,
                url: None,
                headers: Vec::new(),
                cwd: None,
                envs: Vec::new(),
                dotenv: None,
                cmd: Some(cmd),
            }))
        }
    });

    match command {
        Some(Command::Test(args)) => match run_test(args) {
            Ok(code) => ExitCode::from(code),
            Err(msg) => {
                eprintln!("Test failed: {msg}");
                ExitCode::from(EXIT_TEST_FAILED)
            }
        },
        None => {
            // Clap has `arg_required_else_help` set — this arm is unreachable
            // in practice, but we keep a defensive fallback.
            ExitCode::SUCCESS
        }
    }
}

fn run_test(args: TestArgs) -> Result<u8, String> {
    validate_min_score(args.min_score)?;
    let timeout = Duration::from_secs_f64(args.timeout);
    if timeout.is_zero() {
        return Err("--timeout must be greater than zero".to_string());
    }

    let envs = collect_envs(&args)?;
    let cwd = args.cwd.clone();

    let transport = resolve_transport(&args)?;
    let normalized = match transport {
        TransportChoice::Stdio(command) => {
            let mut config = StdioConfig::new(command)
                .with_timeout(timeout)
                .with_max_response_bytes(args.max_response_bytes)
                .with_envs(envs);
            if let Some(cwd) = cwd {
                config = config.with_cwd(cwd);
            }
            let target = config.target();
            let mut t = StdioTransport::spawn(config).map_err(transport_error_message)?;
            scan_via(&mut t, target)?
        }
        TransportChoice::Http(url) => {
            let mut config = HttpConfig::new(url)
                .with_timeout(timeout)
                .with_max_response_bytes(args.max_response_bytes);
            for header in &args.headers {
                let (name, value) = parse_header(header)?;
                config = config.with_header(name, value);
            }
            let target = config.target();
            let mut t = HttpTransport::new(config).map_err(transport_error_message)?;
            scan_via(&mut t, target)?
        }
    };

    let report = scan_server(normalized, 100);
    emit_outputs(&report, &args)?;
    Ok(enforce_min_score(report.score.total_score, args.min_score))
}

enum TransportChoice {
    Stdio(Vec<String>),
    Http(String),
}

fn resolve_transport(args: &TestArgs) -> Result<TransportChoice, String> {
    let kind = args.transport.clone().or_else(|| {
        if args.cmd.is_some() {
            Some(TransportKind::Stdio)
        } else if args.url.is_some() {
            Some(TransportKind::Http)
        } else {
            None
        }
    });

    match kind {
        Some(TransportKind::Stdio) => {
            let command = args
                .cmd
                .clone()
                .ok_or_else(|| "stdio transport requires --cmd".to_string())?;
            if command.is_empty() {
                return Err("--cmd must not be empty".to_string());
            }
            Ok(TransportChoice::Stdio(command))
        }
        Some(TransportKind::Http) => {
            let url = args
                .url
                .clone()
                .ok_or_else(|| "http transport requires --url".to_string())?;
            Ok(TransportChoice::Http(url))
        }
        None => {
            Err("no transport selected; pass --cmd ... for stdio or --url ... for http".to_string())
        }
    }
}

fn scan_via<T: Transport>(transport: &mut T, target: String) -> Result<NormalizedServer, String> {
    transport.scan(target).map_err(transport_error_message)
}

fn emit_outputs(report: &Report, args: &TestArgs) -> Result<(), String> {
    // Always print terminal summary to stdout.
    let terminal = TerminalReporter.render(report);
    let mut stdout = std::io::stdout().lock();
    stdout
        .write_all(terminal.as_bytes())
        .map_err(|e| format!("failed to write terminal output: {e}"))?;

    if let Some(path) = &args.json_out {
        write_report(path, &JsonReporter.render(report))?;
    }
    if let Some(path) = &args.sarif_out {
        write_report(path, &SarifReporter.render(report))?;
    }
    if let Some(path) = &args.markdown_out {
        write_report(path, &MarkdownReporter.render(report))?;
    }
    Ok(())
}

fn write_report(path: &Path, contents: &str) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("could not create {}: {e}", parent.display()))?;
        }
    }
    fs::write(path, contents).map_err(|e| format!("could not write {}: {e}", path.display()))
}

fn enforce_min_score(total_score: u32, min_score: u32) -> u8 {
    if total_score >= min_score {
        EXIT_SUCCESS
    } else {
        eprintln!(
            "Score gate failed: total score {total_score} is below --min-score {min_score}. \
Lower the threshold or fix the reported findings."
        );
        EXIT_SCORE_BELOW_THRESHOLD
    }
}

fn validate_min_score(value: u32) -> Result<(), String> {
    if value > 100 {
        return Err("--min-score must be in the range 0..=100".to_string());
    }
    Ok(())
}

fn parse_header(raw: &str) -> Result<(String, String), String> {
    let (name, value) = raw
        .split_once(':')
        .ok_or_else(|| format!("invalid --header {raw:?}; expected 'Name: Value'"))?;
    let name = name.trim();
    let value = value.trim();
    if name.is_empty() {
        return Err(format!("invalid --header {raw:?}; empty name"));
    }
    Ok((name.to_string(), value.to_string()))
}

/// Merge dotenv file + explicit `--env` flags into a single env list.
/// Explicit `--env` values override dotenv values for the same key.
fn collect_envs(args: &TestArgs) -> Result<Vec<(String, String)>, String> {
    let mut map: HashMap<String, String> = HashMap::new();

    // 1. Auto-detect or use explicit dotenv path.
    let dotenv_path = args.dotenv.clone().unwrap_or_else(|| {
        let base = args.cwd.clone().unwrap_or_else(|| PathBuf::from("."));
        base.join(".env")
    });
    if dotenv_path.is_file() {
        for (key, value) in load_dotenv(&dotenv_path)? {
            map.insert(key, value);
        }
    }

    // 2. Explicit --env flags override dotenv.
    for raw in &args.envs {
        let (key, value) = parse_env_arg(raw)?;
        map.insert(key, value);
    }

    Ok(map.into_iter().collect())
}

fn parse_env_arg(raw: &str) -> Result<(String, String), String> {
    let (key, value) = raw
        .split_once('=')
        .ok_or_else(|| format!("invalid --env {raw:?}; expected 'KEY=VALUE'"))?;
    let key = key.trim();
    if key.is_empty() {
        return Err(format!("invalid --env {raw:?}; empty key"));
    }
    Ok((key.to_string(), value.to_string()))
}

/// Minimal dotenv parser: `KEY=VALUE` lines, `#` comments, blank lines
/// skipped. Supports optional quoting (`KEY="VALUE"` or `KEY='VALUE'`).
fn load_dotenv(path: &Path) -> Result<Vec<(String, String)>, String> {
    let file = fs::File::open(path)
        .map_err(|e| format!("could not open {}: {e}", path.display()))?;
    let reader = std::io::BufReader::new(file);
    let mut entries = Vec::new();
    for (i, line) in reader.lines().enumerate() {
        let line = line.map_err(|e| format!("{}:{}: {e}", path.display(), i + 1))?;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some((key, raw_value)) = trimmed.split_once('=') {
            let key = key.trim();
            if key.is_empty() {
                continue;
            }
            let value = strip_quotes(raw_value.trim());
            entries.push((key.to_string(), value));
        }
    }
    Ok(entries)
}

fn strip_quotes(s: &str) -> String {
    if s.len() >= 2 {
        let bytes = s.as_bytes();
        if (bytes[0] == b'"' && bytes[bytes.len() - 1] == b'"')
            || (bytes[0] == b'\'' && bytes[bytes.len() - 1] == b'\'')
        {
            return s[1..s.len() - 1].to_string();
        }
    }
    s.to_string()
}

/// Expand shorthand argv by prepending a runtime when the first argument
/// looks like a script file: `.ts` → `npx tsx`, `.js` → `node`,
/// `.py` → `python3`. Anything else is passed through unchanged.
fn expand_shorthand(args: Vec<String>) -> Vec<String> {
    if let Some(first) = args.first() {
        let path = Path::new(first);
        if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            let mut cmd: Vec<String> = match ext {
                "ts" | "tsx" => vec!["npx".into(), "tsx".into()],
                "js" | "mjs" | "cjs" => vec!["node".into()],
                "py" => vec!["python3".into()],
                _ => Vec::new(),
            };
            if !cmd.is_empty() {
                cmd.extend(args);
                return cmd;
            }
        }
    }
    args
}

fn transport_error_message(err: TransportError) -> String {
    err.to_string()
}

fn init_tracing(filter: &str) {
    let env_filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(filter))
        .or_else(|_| EnvFilter::try_new("info"))
        .expect("hard-coded `info` filter must parse");
    fmt()
        .with_env_filter(env_filter)
        .with_target(false)
        .with_writer(std::io::stderr)
        .compact()
        .try_init()
        .ok();
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_parses_test_with_cmd() {
        Cli::command().debug_assert();
        let cli = Cli::try_parse_from([
            "mcpunit",
            "test",
            "--min-score",
            "80",
            "--cmd",
            "./my-mcp-server",
            "--flag",
        ])
        .unwrap();
        match cli.command {
            Some(Command::Test(args)) => {
                assert_eq!(args.min_score, 80);
                assert_eq!(
                    args.cmd.as_deref(),
                    Some(["./my-mcp-server".to_string(), "--flag".to_string()].as_slice())
                );
            }
            _ => panic!("expected test command"),
        }
    }

    #[test]
    fn cli_parses_test_with_url_and_headers() {
        let cli = Cli::try_parse_from([
            "mcpunit",
            "test",
            "--url",
            "https://example.com/mcp",
            "--header",
            "Authorization: Bearer abc",
        ])
        .unwrap();
        match cli.command {
            Some(Command::Test(args)) => {
                assert_eq!(args.url.as_deref(), Some("https://example.com/mcp"));
                assert_eq!(args.headers, vec!["Authorization: Bearer abc".to_string()]);
            }
            _ => panic!("expected test command"),
        }
    }

    #[test]
    fn parse_header_splits_name_and_value() {
        assert_eq!(
            parse_header("X-Token: secret").unwrap(),
            ("X-Token".to_string(), "secret".to_string())
        );
    }

    #[test]
    fn parse_header_rejects_empty_name() {
        assert!(parse_header(":value").is_err());
    }

    #[test]
    fn parse_header_rejects_missing_separator() {
        assert!(parse_header("Authorization").is_err());
    }

    #[test]
    fn validate_min_score_accepts_range() {
        assert!(validate_min_score(0).is_ok());
        assert!(validate_min_score(100).is_ok());
        assert!(validate_min_score(101).is_err());
    }

    #[test]
    fn enforce_min_score_returns_zero_on_pass() {
        assert_eq!(enforce_min_score(85, 80), EXIT_SUCCESS);
    }

    #[test]
    fn enforce_min_score_returns_three_on_fail() {
        assert_eq!(enforce_min_score(70, 80), EXIT_SCORE_BELOW_THRESHOLD);
    }
}
