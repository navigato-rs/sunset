//! A commandline SFTP client.
//!
//! Runs a single command per invocation, so it is usable from scripts:
//!
//! ```text
//! sftpc user@host ls /tmp
//! sftpc user@host get /etc/motd
//! ```

#[allow(unused_imports)]
use anyhow::{Context, Result, anyhow, bail};
#[allow(unused_imports)]
use log::{debug, error, info, log, trace, warn};

use std::cell::RefCell;
use std::io::Read as _;
use std::process::ExitCode;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use sunset::{Error, SignKey};
use sunset_async::{ChanInOut, SSHClient};
use sunset_sftp::client::SftpClient;
use sunset_sftp::error::SftpError;
use sunset_sftp::protocol::Attrs;
use sunset_stdasync::{AgentClient, CmdlineClient};

/// Buffer for encoding requests and holding response names.
///
/// Larger than `sunset_sftp::client::DEFAULT_CLIENT_BUF`, which is sized
/// for embedded use, so that long paths and long names fit.
const SFTP_BUF: usize = 8192;

/// Chunk size for transfers.
///
/// The client splits this into `MAX_READ_LEN` sized requests and keeps
/// several in flight, so a chunk covering the whole pipeline costs
/// about one round trip rather than one per request.
const CHUNK: usize = 256 * 1024;

fn main() -> ExitCode {
    let args: Args = argh::from_env();

    let level = if args.debug {
        simplelog::LevelFilter::Debug
    } else {
        simplelog::LevelFilter::Warn
    };
    let conf =
        simplelog::ConfigBuilder::new().add_filter_allow_str("sunset").build();
    let _ = simplelog::TermLogger::init(
        level,
        conf,
        simplelog::TerminalMode::Stderr,
        simplelog::ColorChoice::Auto,
    );

    match run(args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("sftpc: {e:#}");
            ExitCode::FAILURE
        }
    }
}

#[tokio::main]
async fn run(mut args: Args) -> Result<()> {
    if args.username.is_none() {
        // user@host syntax, rsplit for usernames containing @
        if let Some((user, host)) = args.host.rsplit_once('@') {
            args.username = Some(user.into());
            args.host = host.into();
        }
    }
    let username = match args.username.take() {
        Some(u) => u,
        None => whoami::username()?,
    };

    let cmd = Command::parse(&args.cmd)?;

    let mut app = CmdlineClient::new(&username, &args.host);
    app.port(args.port);
    // The sftp subsystem rather than a shell
    app.subsystem("sftp");
    for i in &args.identityfile {
        app.add_authkey(read_key(i).with_context(|| format!("loading key {i}"))?);
    }
    if let Some(agent) = load_agent_keys(&mut app).await {
        app.agent(agent);
    }

    let mut stream = TcpStream::connect((args.host.as_str(), args.port))
        .await
        .with_context(|| format!("connecting to {}:{}", args.host, args.port))?;
    // SFTP alternates a small request with a large reply. Without this,
    // Nagle holds each request back until the peer's delayed ACK,
    // costing tens of milliseconds per round trip.
    if let Err(e) = stream.set_nodelay(true) {
        warn!("Couldn't set TCP_NODELAY: {e}");
    }
    let (mut rsock, mut wsock) = stream.split();

    let ssh = SSHClient::new_owned();
    let ssh_fut = ssh.run_tokio(&mut rsock, &mut wsock);

    // The session future can only return a sunset::Error, so the real
    // failure is passed back here instead.
    let failure = RefCell::new(None);
    let session = app.run_channel(&ssh, |io| sftp_session(io, &cmd, &failure));

    tokio::select! {
        r = ssh_fut => {
            r.context("SSH connection")?;
            bail!("SSH connection closed early")
        }
        r = session => {
            match failure.take() {
                Some(e) => return Err(e),
                None => r.context("SFTP session")?,
            };
        }
    }
    Ok(())
}

/// Runs one command over an established SFTP channel.
///
/// Only a `sunset::Error` can be handed back to the session, so a
/// failure is left in `failure` for the caller to report.
async fn sftp_session(
    io: ChanInOut<'_>,
    cmd: &Command,
    failure: &RefCell<Option<anyhow::Error>>,
) -> sunset::Result<()> {
    let (rx, tx) = io.split();
    let mut client: SftpClient<_, _, SFTP_BUF> = SftpClient::new(rx, tx);

    let r = async {
        client.init().await.context("SFTP handshake")?;
        run_command(&mut client, cmd).await
    }
    .await;

    match r {
        Ok(()) => Ok(()),
        Err(e) => {
            *failure.borrow_mut() = Some(e);
            Err(Error::msg("SFTP command failed"))
        }
    }
}

/// What to do once connected.
#[derive(Debug)]
enum Command {
    List { path: String },
    Get { remote: String, local: String },
    Put { local: String, remote: String },
    Remove { path: String },
    MkDir { path: String },
    RmDir { path: String },
    Rename { old: String, new: String },
    Stat { path: String },
    Symlink { target: String, link: String },
    ReadLink { path: String },
    RealPath { path: String },
}

impl Command {
    fn parse(args: &[String]) -> Result<Self> {
        let (name, rest) = args
            .split_first()
            .with_context(|| format!("no command given.{USAGE}"))?;
        let arg = |n: usize| -> Result<String> {
            rest.get(n)
                .cloned()
                .with_context(|| format!("{name} needs more arguments"))
        };
        // The trailing component of a path, for defaulted arguments
        let base =
            |p: &str| -> String { p.rsplit('/').next().unwrap_or(p).to_string() };

        let c = match name.as_str() {
            "ls" | "dir" => {
                Self::List { path: rest.first().cloned().unwrap_or(".".into()) }
            }
            "get" => {
                let remote = arg(0)?;
                let local = rest.get(1).cloned().unwrap_or_else(|| base(&remote));
                Self::Get { remote, local }
            }
            "put" => {
                let local = arg(0)?;
                let remote = rest.get(1).cloned().unwrap_or_else(|| base(&local));
                Self::Put { local, remote }
            }
            "rm" => Self::Remove { path: arg(0)? },
            "mkdir" => Self::MkDir { path: arg(0)? },
            "rmdir" => Self::RmDir { path: arg(0)? },
            "mv" | "rename" => Self::Rename { old: arg(0)?, new: arg(1)? },
            "stat" => Self::Stat { path: arg(0)? },
            "ln" | "symlink" => Self::Symlink { target: arg(0)?, link: arg(1)? },
            "readlink" => Self::ReadLink { path: arg(0)? },
            "realpath" => Self::RealPath { path: arg(0)? },
            _ => bail!("unknown command \"{name}\".{USAGE}"),
        };
        Ok(c)
    }
}

const USAGE: &str = "
Commands:
  ls [PATH]              list a directory
  get REMOTE [LOCAL]     download a file
  put LOCAL [REMOTE]     upload a file
  rm PATH                remove a file
  mkdir PATH             create a directory
  rmdir PATH             remove an empty directory
  mv OLD NEW             rename
  stat PATH              show attributes
  ln TARGET LINK         create a symlink
  readlink PATH          show a symlink's target
  realpath PATH          canonicalise a path";

async fn run_command<R, W, const N: usize>(
    client: &mut SftpClient<R, W, N>,
    cmd: &Command,
) -> Result<()>
where
    R: sunset_sftp::embedded_io_async::Read,
    W: sunset_sftp::embedded_io_async::Write,
{
    match cmd {
        Command::List { path } => list(client, path).await,
        Command::Get { remote, local } => get(client, remote, local).await,
        Command::Put { local, remote } => put(client, local, remote).await,
        Command::Remove { path } => {
            client.remove(path).await.with_context(|| format!("removing {path}"))
        }
        Command::MkDir { path } => client
            .mkdir(path, &Attrs::default())
            .await
            .with_context(|| format!("creating {path}")),
        Command::RmDir { path } => {
            client.rmdir(path).await.with_context(|| format!("removing {path}"))
        }
        Command::Rename { old, new } => {
            // posix-rename replaces the destination, which is what
            // people expect of "mv". Fall back where unsupported.
            let r = if client.extensions().posix_rename {
                client.posix_rename(old, new).await
            } else {
                client.rename(old, new).await
            };
            r.with_context(|| format!("renaming {old} to {new}"))
        }
        Command::Stat { path } => {
            let a =
                client.stat(path).await.with_context(|| format!("stat {path}"))?;
            println!("{path}");
            if let Some(s) = a.size {
                println!("  size        {s}");
            }
            if let Some(p) = a.permissions {
                println!("  permissions {:o}", p & 0o7777);
            }
            if let (Some(u), Some(g)) = (a.uid, a.gid) {
                println!("  uid/gid     {u}/{g}");
            }
            if let Some(m) = a.mtime {
                println!("  mtime       {m}");
            }
            Ok(())
        }
        Command::Symlink { target, link } => client
            .symlink(target, link)
            .await
            .with_context(|| format!("linking {link} to {target}")),
        Command::ReadLink { path } => {
            let mut buf = [0u8; SFTP_BUF];
            let t = client
                .readlink(path, &mut buf)
                .await
                .with_context(|| format!("readlink {path}"))?;
            println!("{}", String::from_utf8_lossy(t));
            Ok(())
        }
        Command::RealPath { path } => {
            let mut buf = [0u8; SFTP_BUF];
            let t = client
                .realpath(path, &mut buf)
                .await
                .with_context(|| format!("realpath {path}"))?;
            println!("{}", String::from_utf8_lossy(t));
            Ok(())
        }
    }
}

async fn list<R, W, const N: usize>(
    client: &mut SftpClient<R, W, N>,
    path: &str,
) -> Result<()>
where
    R: sunset_sftp::embedded_io_async::Read,
    W: sunset_sftp::embedded_io_async::Write,
{
    let dir =
        client.opendir(path).await.with_context(|| format!("opening {path}"))?;

    let mut listed = Ok(());
    'outer: loop {
        match client.readdir(&dir).await {
            Ok(None) => break,
            Ok(Some(mut entries)) => {
                loop {
                    match entries.next().await {
                        Ok(None) => break,
                        Ok(Some(e)) => {
                            // The long name is a server formatted "ls -l"
                            // line. Fall back to just the name.
                            if e.longname().is_empty() {
                                println!(
                                    "{}",
                                    String::from_utf8_lossy(e.filename())
                                );
                            } else {
                                println!(
                                    "{}",
                                    String::from_utf8_lossy(e.longname())
                                );
                            }
                        }
                        Err(e) => {
                            listed = Err(e).context("reading directory entry");
                            break 'outer;
                        }
                    }
                }
            }
            Err(e) => {
                listed = Err(e).context("reading directory");
                break;
            }
        }
    }

    // Close the handle even after a failure, the listing may be partial
    let closed = client.close(&dir).await.context("closing directory");
    listed.and(closed)
}

async fn get<R, W, const N: usize>(
    client: &mut SftpClient<R, W, N>,
    remote: &str,
    local: &str,
) -> Result<()>
where
    R: sunset_sftp::embedded_io_async::Read,
    W: sunset_sftp::embedded_io_async::Write,
{
    let h = client
        .open_read(remote)
        .await
        .with_context(|| format!("opening {remote}"))?;

    let r = async {
        let mut out = tokio::fs::File::create(local)
            .await
            .with_context(|| format!("creating {local}"))?;
        let mut buf = vec![0u8; CHUNK];
        let mut offset = 0u64;
        loop {
            let n = client
                .read(&h, offset, &mut buf)
                .await
                .with_context(|| format!("reading {remote}"))?;
            if n == 0 {
                break;
            }
            out.write_all(&buf[..n]).await.context("writing local file")?;
            offset += n as u64;
        }
        out.flush().await.context("writing local file")?;
        debug!("{remote} -> {local}, {offset} bytes");
        Ok(())
    }
    .await;

    let closed = client.close(&h).await.context("closing remote file");
    r.and(closed)
}

async fn put<R, W, const N: usize>(
    client: &mut SftpClient<R, W, N>,
    local: &str,
    remote: &str,
) -> Result<()>
where
    R: sunset_sftp::embedded_io_async::Read,
    W: sunset_sftp::embedded_io_async::Write,
{
    let mut input = tokio::fs::File::open(local)
        .await
        .with_context(|| format!("opening {local}"))?;

    let h =
        client.create(remote).await.with_context(|| format!("creating {remote}"))?;

    let r = async {
        let mut buf = vec![0u8; CHUNK];
        let mut offset = 0u64;
        loop {
            let n = input.read(&mut buf).await.context("reading local file")?;
            if n == 0 {
                break;
            }
            client
                .write(&h, offset, &buf[..n])
                .await
                .with_context(|| format!("writing {remote}"))?;
            offset += n as u64;
        }
        debug!("{local} -> {remote}, {offset} bytes");
        Ok(())
    }
    .await;

    let closed = client.close(&h).await.context("closing remote file");
    r.and(closed)
}

/// `SftpError` doesn't implement `std::error::Error`, so it can't be
/// used with `?` and `context()` directly.
trait SftpContext<T> {
    fn with_context<C, F>(self, f: F) -> Result<T>
    where
        C: std::fmt::Display + Send + Sync + 'static,
        F: FnOnce() -> C;
    fn context<C>(self, c: C) -> Result<T>
    where
        C: std::fmt::Display + Send + Sync + 'static;
}

impl<T> SftpContext<T> for Result<T, SftpError> {
    fn with_context<C, F>(self, f: F) -> Result<T>
    where
        C: std::fmt::Display + Send + Sync + 'static,
        F: FnOnce() -> C,
    {
        self.map_err(|e| anyhow!("{}: {}", f(), describe(&e)))
    }

    fn context<C>(self, c: C) -> Result<T>
    where
        C: std::fmt::Display + Send + Sync + 'static,
    {
        self.map_err(|e| anyhow!("{}: {}", c, describe(&e)))
    }
}

/// A readable description of a SFTP failure.
fn describe(e: &SftpError) -> String {
    use sunset_sftp::protocol::StatusCode;
    match e {
        SftpError::FileServerError(s) => match s {
            StatusCode::SSH_FX_NO_SUCH_FILE => "no such file".into(),
            StatusCode::SSH_FX_PERMISSION_DENIED => "permission denied".into(),
            StatusCode::SSH_FX_OP_UNSUPPORTED => {
                "not supported by the server".into()
            }
            StatusCode::SSH_FX_EOF => "unexpected end of file".into(),
            s => format!("server error {s:?}"),
        },
        e => format!("{e:?}"),
    }
}

#[derive(argh::FromArgs, Debug)]
/// Sunset SFTP client. Run with no command for a list of commands.
struct Args {
    #[argh(switch, short = 'v')]
    /// verbose debug logging
    debug: bool,

    #[argh(option, short = 'i')]
    /// a path to id_ed25519 or similar
    identityfile: Vec<String>,

    #[argh(option, short = 'l')]
    /// username
    username: Option<String>,

    #[argh(option, short = 'p', default = "22")]
    /// port
    port: u16,

    #[argh(positional)]
    /// host to connect to, as [user@]host
    host: String,

    #[argh(positional, greedy)]
    /// command and arguments
    cmd: Vec<String>,
}

fn read_key(p: &str) -> Result<SignKey> {
    let mut v = vec![];
    std::fs::File::open(p)?.read_to_end(&mut v)?;
    SignKey::from_openssh(v).map_err(|e| anyhow!("parsing openssh key: {e}"))
}

async fn load_agent_keys(app: &mut CmdlineClient) -> Option<AgentClient> {
    let e = std::env::var("SSH_AUTH_SOCK").ok()?;
    let mut agent = match AgentClient::new(e).await {
        Ok(a) => a,
        Err(e) => {
            warn!("Error opening agent: {e}");
            return None;
        }
    };
    let keys = match agent.keys().await {
        Ok(k) => k,
        Err(e) => {
            warn!("Error fetching agent keys: {e}");
            return None;
        }
    };
    trace!("Loaded {} agent keys", keys.len());
    for k in keys {
        app.add_authkey(k)
    }
    Some(agent)
}
