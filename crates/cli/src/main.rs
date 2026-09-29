//! `sandcastle`: signs calls to a node's API with a key file and prints the
//! answer. The key is read from a file by path, never from the command line.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use sandcastle_nip98::Keys;
use sandcastle_proto::{ComputerSpec, GrantSpec};

#[derive(Parser)]
#[command(name = "sandcastle", about = "A signed client for sandcastle nodes.")]
struct Cli {
    /// The node's API, e.g. https://api.sandcastle.example
    #[arg(long, env = "SANDCASTLE_API")]
    api: Option<String>,
    /// A file holding the signing key (64 hex); made by `keygen`.
    #[arg(long, env = "SANDCASTLE_KEY_FILE")]
    key_file: Option<PathBuf>,
    /// An extra trusted CA (PEM), for a node with a private certificate.
    #[arg(long, env = "SANDCASTLE_CA_FILE")]
    ca_file: Option<PathBuf>,
    /// Connect to this address instead of resolving the API's host (the
    /// TLS name and the signed URL stay the API's).
    #[arg(long)]
    connect: Option<SocketAddr>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Make a signing key in a new file (mode 0600) and print its public key.
    Keygen { #[arg(long)] out: PathBuf },
    /// Print the public key of --key-file.
    Pubkey,
    /// Health check (unsigned).
    Health,
    /// Grant a key compute on the node (grantors only).
    Grant {
        pubkey: String,
        #[arg(long)] computers: u32,
        #[arg(long)] vcpus: u32,
        #[arg(long)] memory_mib: u32,
        #[arg(long)] data_gib: u32,
    },
    /// Show a key's grant (the key itself, or a grantor).
    GrantOf { pubkey: String },
    /// Revoke a key's grant; its computers stop (grantors only).
    Revoke { pubkey: String },
    /// Create a computer, or converge it to a spec (JSON file).
    Put { name: String, #[arg(long)] spec: PathBuf },
    Get { name: String },
    List,
    Start { name: String },
    Stop { name: String },
    /// Delete a computer and its durable disk. Irreversible.
    Delete { name: String },
    /// A single-use link that opens the computer's URL in a browser.
    Ticket { name: String },
    /// The node's snapshots of a computer's durable disk, oldest first.
    Snapshots { name: String },
}

fn fail(msg: impl std::fmt::Display) -> ! {
    eprintln!("sandcastle: {msg}");
    std::process::exit(1)
}

fn now() -> i64 {
    let since = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).expect("the clock is after 1970");
    i64::try_from(since.as_secs()).expect("seconds fit in i64")
}

fn keys(cli: &Cli) -> Keys {
    let path = cli.key_file.as_ref().unwrap_or_else(|| fail("--key-file (or SANDCASTLE_KEY_FILE) is needed"));
    let secret = std::fs::read_to_string(path).unwrap_or_else(|e| fail(format!("{}: {e}", path.display())));
    Keys::from_secret_hex(&secret).unwrap_or_else(|| fail(format!("{}: not a 64-hex secret key", path.display())))
}

fn keygen(out: &PathBuf) {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let k = Keys::generate();
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(out)
        .unwrap_or_else(|e| fail(format!("{}: {e}", out.display())));
    f.write_all(format!("{}\n", k.secret_hex()).as_bytes()).unwrap_or_else(|e| fail(e));
    println!("{}", k.pubkey_hex());
}

fn tls_config(ca_file: Option<&PathBuf>) -> rustls::ClientConfig {
    use rustls_pki_types::pem::PemObject;
    let mut roots = rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
    if let Some(ca) = ca_file {
        let certs = rustls_pki_types::CertificateDer::pem_file_iter(ca).unwrap_or_else(|e| fail(format!("{}: {e}", ca.display())));
        for c in certs {
            roots.add(c.unwrap_or_else(|e| fail(format!("{}: {e}", ca.display())))).unwrap_or_else(|e| fail(e));
        }
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("ring supports the default versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    config
}

/// One HTTPS request to the node; returns the status and body.
async fn request(cli: &Cli, method: &str, path: &str, body: Vec<u8>, keys: Option<&Keys>) -> (u16, Vec<u8>) {
    let api = cli.api.as_deref().unwrap_or_else(|| fail("--api (or SANDCASTLE_API) is needed"));
    let base = url::Url::parse(api).unwrap_or_else(|e| fail(format!("--api: {e}")));
    if base.scheme() != "https" {
        fail("--api is https");
    }
    let host = base.host_str().unwrap_or_else(|| fail("--api has no host")).to_string();
    let port = base.port_or_known_default().unwrap_or(443);
    let url = format!("https://{host}{}{path}", if port == 443 { String::new() } else { format!(":{port}") });
    let addr = match cli.connect {
        Some(a) => a,
        None => tokio::net::lookup_host((host.as_str(), port))
            .await
            .unwrap_or_else(|e| fail(format!("{host}: {e}")))
            .next()
            .unwrap_or_else(|| fail(format!("{host}: no address"))),
    };
    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap_or_else(|e| fail(format!("{addr}: {e}")));
    let connector = tokio_rustls::TlsConnector::from(Arc::new(tls_config(cli.ca_file.as_ref())));
    let name = rustls_pki_types::ServerName::try_from(host.clone()).unwrap_or_else(|e| fail(e));
    let tls = connector.connect(name, tcp).await.unwrap_or_else(|e| fail(format!("TLS to {host}: {e}")));
    let (mut send, conn) = hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(tls)).await.unwrap_or_else(|e| fail(e));
    tokio::spawn(conn);
    let mut req = hyper::Request::builder().method(method).uri(path).header("host", &host).header("content-type", "application/json");
    if let Some(k) = keys {
        req = req.header("authorization", k.header(method, &url, &body, now()));
    }
    let req = req.body(Full::new(Bytes::from(body))).expect("a request builds");
    let resp = send.send_request(req).await.unwrap_or_else(|e| fail(e));
    let status = resp.status().as_u16();
    let bytes = resp.into_body().collect().await.unwrap_or_else(|e| fail(e)).to_bytes();
    (status, bytes.to_vec())
}

async fn call(cli: &Cli, method: &str, path: &str, body: Option<serde_json::Value>) {
    let k = keys(cli);
    let bytes = body.map(|b| serde_json::to_vec(&b).expect("JSON serializes")).unwrap_or_default();
    let (status, answer) = request(cli, method, path, bytes, Some(&k)).await;
    let text = String::from_utf8_lossy(&answer);
    match serde_json::from_str::<serde_json::Value>(&text) {
        Ok(v) => println!("{}", serde_json::to_string_pretty(&v).expect("JSON serializes")),
        Err(_) => println!("{text}"),
    }
    if status >= 400 {
        std::process::exit(1);
    }
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    match &cli.command {
        Command::Keygen { out } => keygen(out),
        Command::Pubkey => println!("{}", keys(&cli).pubkey_hex()),
        Command::Health => {
            let (status, body) = request(&cli, "GET", "/v1/health", Vec::new(), None).await;
            println!("{}", String::from_utf8_lossy(&body));
            if status >= 400 {
                std::process::exit(1);
            }
        }
        Command::Grant { pubkey, computers, vcpus, memory_mib, data_gib } => {
            let g = GrantSpec { computers_max: *computers, vcpus_max: *vcpus, memory_mib_max: *memory_mib, data_gib_max: *data_gib };
            call(&cli, "PUT", &format!("/v1/grants/{pubkey}"), Some(serde_json::to_value(g).expect("serializes"))).await
        }
        Command::GrantOf { pubkey } => call(&cli, "GET", &format!("/v1/grants/{pubkey}"), None).await,
        Command::Revoke { pubkey } => call(&cli, "DELETE", &format!("/v1/grants/{pubkey}"), None).await,
        Command::Put { name, spec } => {
            let raw = std::fs::read(spec).unwrap_or_else(|e| fail(format!("{}: {e}", spec.display())));
            let parsed: ComputerSpec = serde_json::from_slice(&raw).unwrap_or_else(|e| fail(format!("{}: {e}", spec.display())));
            if let Err(e) = parsed.validate() {
                fail(format!("{}: {e}", spec.display()));
            }
            call(&cli, "PUT", &format!("/v1/computers/{name}"), Some(serde_json::to_value(parsed).expect("serializes"))).await
        }
        Command::Get { name } => call(&cli, "GET", &format!("/v1/computers/{name}"), None).await,
        Command::List => call(&cli, "GET", "/v1/computers", None).await,
        Command::Start { name } => call(&cli, "POST", &format!("/v1/computers/{name}/start"), None).await,
        Command::Stop { name } => call(&cli, "POST", &format!("/v1/computers/{name}/stop"), None).await,
        Command::Delete { name } => call(&cli, "DELETE", &format!("/v1/computers/{name}"), None).await,
        Command::Ticket { name } => call(&cli, "POST", &format!("/v1/computers/{name}/tickets"), None).await,
        Command::Snapshots { name } => call(&cli, "GET", &format!("/v1/computers/{name}/snapshots"), None).await,
    }
}
