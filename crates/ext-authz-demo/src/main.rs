//! ext-authz-demo — run the reference external-authorization middleware end-to-end.
//!
//!   ext-authz-demo demo                       # self-contained: spins the verifier + runs scenarios
//!   ext-authz-demo verifier --listen 127.0.0.1:18443 --key-hex <hex>   # run the guard service alone
//!
//! The `demo` subcommand is also the smoke test: it asserts the expected reason code
//! for every scenario and exits non-zero on any mismatch.

mod driver;
mod token;
mod verifier;

use std::net::SocketAddr;

use clap::{Parser, Subcommand};
use verifier::VerifierState;

#[derive(Parser)]
#[command(
    name = "ext-authz-demo",
    about = "OpenShell ext-authz middleware reference demo"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Spin a verifier in-process and run the full scenario suite (self-contained).
    Demo {
        /// Walk the scenarios one at a time, with pauses — good for a screen recording.
        #[arg(long)]
        story: bool,
        /// Pause between scenarios in story mode, in milliseconds.
        #[arg(long, default_value_t = 1100)]
        pause_ms: u64,
    },
    /// Run the reference verifier ("guard service") as a standalone server.
    Verifier {
        #[arg(long, default_value = "127.0.0.1:18443")]
        listen: String,
        /// HMAC key as hex. Default decodes to `token::DEMO_KEY` (NOT for production).
        #[arg(long, default_value = "64656d6f2d6861776378")]
        key_hex: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_target(false)
        .init();
    match Cli::parse().cmd {
        Cmd::Verifier { listen, key_hex } => run_verifier(listen, key_hex).await,
        Cmd::Demo { story, pause_ms } => run_demo(story, pause_ms).await,
    }
}

async fn run_verifier(listen: String, key_hex: String) -> anyhow::Result<()> {
    let key = hex::decode(key_hex)?;
    let addr: SocketAddr = listen.parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("ext-authz reference verifier listening on http://{addr}/v1/authorize");
    axum::serve(listener, verifier::router(VerifierState::new(key))).await?;
    Ok(())
}

async fn run_demo(story: bool, pause_ms: u64) -> anyhow::Result<()> {
    let key = token::DEMO_KEY.to_vec();

    // Verifier on an ephemeral port.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let verifier_url = format!("http://{addr}/v1/authorize");
    let key2 = key.clone();
    tokio::spawn(async move {
        let _ = axum::serve(listener, verifier::router(VerifierState::new(key2))).await;
    });
    // A closed port for the fail-closed scenario (bind then drop).
    let down_url = {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let a = l.local_addr()?;
        drop(l);
        format!("http://{a}/v1/authorize")
    };

    let results = driver::run_scenarios(&verifier_url, &key, &down_url).await;

    if story {
        render_story(&results, &verifier_url, pause_ms).await;
    } else {
        render_table(&results, &verifier_url);
    }

    if results.iter().all(|r| r.passed()) {
        println!("  {} scenarios, all as expected.\n", results.len());
        Ok(())
    } else {
        anyhow::bail!("one or more scenarios did not match the expected outcome")
    }
}

/// The compact all-at-once table (also the CI smoke-test view).
fn render_table(results: &[driver::ScenarioResult], verifier_url: &str) {
    println!("\n  OpenShell ext-authz middleware — reference demo");
    println!("  verifier: {verifier_url}\n");
    for r in results {
        let mark = if r.passed() { "ok " } else { "BAD" };
        let verdict = if r.got_allow { "ALLOW" } else { "DENY " };
        let lat = r
            .audit
            .verifier_latency_ms
            .map(|m| format!("{m:.2}ms"))
            .unwrap_or_else(|| "-".into());
        println!(
            "  [{mark}] {verdict} {:<28} {:<46} (verifier {lat})",
            r.got_reason, r.name
        );
    }
    println!("\n  --- one audit event (JSON) ---");
    if let Some(first) = results.first() {
        if let Ok(j) = serde_json::to_string(&first.audit) {
            println!("  {j}");
        }
    }
    println!();
}

/// Walk the scenarios one at a time with pauses — built to be screen-recorded.
async fn render_story(results: &[driver::ScenarioResult], verifier_url: &str, pause_ms: u64) {
    use std::io::Write;
    use tokio::time::{sleep, Duration};

    let c = Colors::detect();
    let rule = "  ────────────────────────────────────────────────────────────────";
    println!();
    println!(
        "  {}OpenShell ext-authz — per-action authorization, one request at a time{}",
        c.bold, c.reset
    );
    println!("  {}verifier {verifier_url}{}", c.dim, c.reset);

    let n = results.len();
    for (i, r) in results.iter().enumerate() {
        println!("{rule}");
        println!(
            "  {}scenario {} of {}{}   {}{}{}",
            c.dim,
            i + 1,
            n,
            c.reset,
            c.bold,
            r.name,
            c.reset
        );
        println!();
        println!("  {}why{}      {}", c.dim, c.reset, r.narrative);
        println!();
        println!(
            "  request   {} {}{}",
            r.audit.method, r.audit.authority, r.audit.path
        );
        println!(
            "            agent  {} · sandbox {}",
            r.audit.agent_id, r.audit.sandbox_id
        );
        if !r.body_preview.is_empty() {
            println!(
                "            body   {}  {}({} bytes){}",
                r.body_preview, c.dim, r.body_len, c.reset
            );
        }
        let tok = if r.token_present {
            "x-hawcx-haap-token: present"
        } else {
            "(none)"
        };
        println!("            token  {tok}");
        println!();

        print!(
            "  {}-> ext-authz: hashing the egress bytes, asking the verifier ...{}",
            c.dim, c.reset
        );
        let _ = std::io::stdout().flush();
        sleep(Duration::from_millis(650)).await;
        println!();
        println!();

        if let Some(req_crh) = &r.crh_hex {
            match &r.bound_crh {
                Some(bound) => {
                    println!("  crh       request     {}", short(req_crh));
                    println!(
                        "            token-bound {}   {}!= bytes changed after mint{}",
                        short(bound),
                        c.red,
                        c.reset
                    );
                }
                None => println!(
                    "  crh       {}  {}(over the bytes that egress){}",
                    short(req_crh),
                    c.dim,
                    c.reset
                ),
            }
            println!();
        }

        let (mark, col) = if r.got_allow {
            ("ALLOW", c.green)
        } else {
            ("DENY", c.red)
        };
        let status = r
            .http_status
            .map(|s| format!("  ·  HTTP {s}"))
            .unwrap_or_default();
        let lat = r
            .audit
            .verifier_latency_ms
            .map(|m| format!("{m:.2} ms"))
            .unwrap_or_else(|| "—".into());
        println!(
            "  verdict   {}{}{}  ·  {}{}",
            col, mark, c.reset, r.got_reason, status
        );
        println!("            {}{}{}", c.dim, r.message, c.reset);
        println!("            {}verifier {lat}{}", c.dim, c.reset);
        if !r.passed() {
            println!(
                "  {}MISMATCH — expected {}/{}{}",
                c.red,
                if r.expect_allow { "allow" } else { "deny" },
                r.expect_reason,
                c.reset
            );
        }
        println!();
        if let Ok(j) = serde_json::to_string(&r.audit) {
            println!("  {}audit{}    {}{j}{}", c.dim, c.reset, c.dim, c.reset);
        }
        sleep(Duration::from_millis(pause_ms)).await;
    }
    println!("{rule}");
}

/// ANSI colors, disabled when stdout is not a terminal (so piped output stays clean).
struct Colors {
    bold: &'static str,
    dim: &'static str,
    red: &'static str,
    green: &'static str,
    reset: &'static str,
}

impl Colors {
    fn detect() -> Self {
        use std::io::IsTerminal;
        if std::io::stdout().is_terminal() {
            Colors {
                bold: "\x1b[1m",
                dim: "\x1b[2m",
                red: "\x1b[31m",
                green: "\x1b[32m",
                reset: "\x1b[0m",
            }
        } else {
            Colors {
                bold: "",
                dim: "",
                red: "",
                green: "",
                reset: "",
            }
        }
    }
}

/// Abbreviate a long hex digest as `prefix…suffix` for terminal display.
fn short(h: &str) -> String {
    if h.len() <= 20 {
        h.to_string()
    } else {
        format!("{}…{}", &h[..8], &h[h.len() - 8..])
    }
}
