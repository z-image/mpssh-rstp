use ssh2::Session;
use std::fmt;
use std::io::Read;
use std::net::TcpStream;
use std::path::Path;
use std::time;

// <russh> ////////////////////////////////////////////////////////////////

use std::sync::{Arc, OnceLock};

use anyhow::{Context, Result};
use async_trait::async_trait;
use byteorder::{BigEndian, ByteOrder};
use russh::keys;
use russh::{Channel, ChannelMsg};
use russh::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;

/* <ssh agent forwarding> */

/// Limits concurrent connections to the local SSH agent socket to avoid
/// overwhelming its listen backlog under high parallelism.
static AGENT_SEMAPHORE: OnceLock<tokio::sync::Semaphore> = OnceLock::new();

fn agent_semaphore() -> &'static tokio::sync::Semaphore {
    AGENT_SEMAPHORE.get_or_init(|| tokio::sync::Semaphore::new(64))
}

/// Connect to the local SSH agent ($SSH_AUTH_SOCK).
///
/// The agent's listen backlog can be tiny (gcr-ssh-agent uses 5), so a burst
/// of sessions can get EAGAIN on connect even under the semaphore. Only the
/// connect is retried; requests sent over an open connection never are.
async fn connect_agent() -> std::io::Result<tokio::net::UnixStream> {
    let path = std::env::var("SSH_AUTH_SOCK").map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::NotFound, "SSH_AUTH_SOCK not set")
    })?;
    retry_on_eagain("agent socket", || tokio::net::UnixStream::connect(&path)).await
}

/// Exchange a message with the local SSH agent.
/// Acquires a semaphore permit to limit concurrent agent connections.
async fn exchange_ssh_agent_message(data: &[u8]) -> std::io::Result<Vec<u8>> {
    let _permit = agent_semaphore().acquire().await.unwrap();
    let mut stream = connect_agent().await?;

    log::debug!("exchange_ssh_agent_message: connected to agent");

    // Write request to agent
    stream.write_all(data).await?;

    log::debug!("exchange_ssh_agent_message: wrote request to agent");

    // Read response with proper message boundary handling
    let mut buf = Vec::new();
    let mut bytes_read = 0;
    let mut expected_len = None;

    loop {
        log::debug!("exchange_ssh_agent_message: reading from agent");
        let n = stream.read_buf(&mut buf).await?;
        if n == 0 {
            break; // EOF
        }

        bytes_read += n;
        log::debug!("exchange_ssh_agent_message: read {} bytes", n);

        // Try to read message length if we haven't yet
        if expected_len.is_none() && buf.len() >= 4 {
            expected_len = Some(BigEndian::read_u32(&buf[0..4]) as usize + 4);
        }

        // Check if we have a complete message
        if let Some(total_len) = expected_len {
            if bytes_read == total_len {
                log::debug!("exchange_ssh_agent_message: read complete message");
                break;
            }
            if bytes_read > total_len {
                log::error!("Read too many bytes");
            }
        }
    }

    stream.shutdown().await?;

    Ok(buf)
}

/// Handle agent forwarding for a channel.
/// This runs as a background task, reading from the channel and forwarding to the local agent.
async fn handle_agent_forward_channel(mut channel: Channel<client::Msg>) {
    log::debug!("Agent forward handler started for channel {:?}", channel.id());

    let mut buffer = Vec::new();

    loop {
        match channel.wait().await {
            Some(ChannelMsg::Data { data }) => {
                log::debug!("Agent forward: received {} bytes", data.len());
                buffer.extend_from_slice(&data);

                // Process complete messages
                while buffer.len() >= 4 {
                    let msg_len = BigEndian::read_u32(&buffer[0..4]) as usize;

                    if buffer.len() < msg_len + 4 {
                        // Wait for more data
                        break;
                    }

                    // Extract the complete message
                    let message: Vec<u8> = buffer.drain(0..4 + msg_len).collect();
                    log::debug!("Agent forward: processing message of length {}", msg_len);

                    // Forward to local agent and send response back
                    match exchange_ssh_agent_message(&message).await {
                        Ok(response) => {
                            log::debug!("Agent forward: got response of {} bytes", response.len());
                            if let Err(e) = channel.data(&response[..]).await {
                                log::error!("Agent forward: failed to send response: {}", e);
                                return;
                            }
                        }
                        Err(e) => {
                            log::error!("Agent forward: failed to exchange with agent: {}", e);
                            return;
                        }
                    }
                }
            }
            Some(ChannelMsg::Eof) => {
                log::debug!("Agent forward: received EOF");
                break;
            }
            Some(ChannelMsg::Close) => {
                log::debug!("Agent forward: channel closed");
                break;
            }
            Some(other) => {
                log::debug!("Agent forward: ignoring message {:?}", other);
            }
            None => {
                log::debug!("Agent forward: channel ended");
                break;
            }
        }
    }

    log::debug!("Agent forward handler finished for channel {:?}", channel.id());
}

/* </ssh agent forwarding> */

/* <ssh client> */

struct Client {
    host: String,
    port: u16,
}

impl Client {
    pub fn new(host: &str, port: u16) -> Self {
        Self {
            host: host.to_string(),
            port,
        }
    }
}

impl client::Handler for Client {
    type Error = russh::Error;

    /// Callback to check the server's public key against a known_hosts file.
    fn check_server_key(
        &mut self,
        server_public_key: &keys::ssh_key::PublicKey,
    ) -> impl std::future::Future<Output = Result<bool, Self::Error>> + Send {
        let host = self.host.clone();
        let port = self.port;
        async move {
            let result = keys::check_known_hosts(&host, port, server_public_key);
            log::debug!("check_server_key: {:?}", result);

            match result {
                Ok(true) => Ok(true),
                _ => Ok(false),
            }
        }
    }

    /// Callback to handle an agent forwarding channel opened by the server.
    /// We spawn a background task to handle the forwarding.
    fn server_channel_open_agent_forward(
        &mut self,
        channel: Channel<client::Msg>,
        _session: &mut client::Session,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send {
        log::debug!("server_channel_open_agent_forward: {:?}", channel.id());

        // Spawn a background task to handle the agent forwarding
        tokio::spawn(handle_agent_forward_channel(channel));

        async { Ok(()) }
    }
}

/* </ssh client> */

/* <remote exec interface> */

pub struct CommandResult {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub exit_code: u32,
    /// Why the command did not exit normally (signal, no exit status).
    /// Printed after the output, which is kept.
    pub failure: Option<String>,
}

/// Exit code reported when the remote command has no exit status of its own,
/// as OpenSSH's ssh does.
const EXIT_CODE_NO_STATUS: u32 = 255;

/// Collects a remote command's output and how it ended.
#[derive(Default)]
struct OutcomeCollector {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    exit_status: Option<u32>,
    exit_signal: Option<String>,
}

impl OutcomeCollector {
    fn feed(&mut self, msg: ChannelMsg) {
        match msg {
            ChannelMsg::Data { data } => self.stdout.extend_from_slice(&data),
            ChannelMsg::ExtendedData { data, .. } => self.stderr.extend_from_slice(&data),
            ChannelMsg::ExitStatus { exit_status } => self.exit_status = Some(exit_status),
            ChannelMsg::ExitSignal { signal_name, error_message, .. } => {
                // russh names only some signals; the rest (XCPU, ...) are Custom.
                let name = match signal_name {
                    Sig::Custom(name) => name,
                    named => format!("{named:?}"),
                };
                self.exit_signal = Some(if error_message.is_empty() {
                    name
                } else {
                    format!("{name} ({error_message})")
                });
            }
            _ => (),
        }
    }

    fn finish(self) -> CommandResult {
        let (exit_code, failure) = match (self.exit_signal, self.exit_status) {
            (Some(signal), _) => (
                EXIT_CODE_NO_STATUS,
                Some(format!("exec: killed by signal {signal}")),
            ),
            (None, Some(status)) => (status, None),
            (None, None) => (
                EXIT_CODE_NO_STATUS,
                Some("exec: channel closed without exit status".to_string()),
            ),
        };
        CommandResult {
            stdout: self.stdout,
            stderr: self.stderr,
            exit_code,
            failure,
        }
    }
}

fn check_auth(result: &client::AuthResult) -> Result<()> {
    if result.success() {
        Ok(())
    } else {
        anyhow::bail!("rejected by server")
    }
}

fn first_identity<T>(identities: Vec<T>) -> Result<T> {
    identities
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("agent has no identities"))
}

#[async_trait]
pub trait RemoteExecutor {
    async fn run_command(&self, command: &str) -> Result<CommandResult>;
}

/* </remote exec interface> */

/* <server config interface> */

#[derive(Clone)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: Option<String>,
}

/* </server config interface> */

/* <main> */

pub struct RusshExecutor {
    config: ServerConfig,
}

#[async_trait]
impl RemoteExecutor for RusshExecutor {
    async fn run_command(&self, command: &str) -> Result<CommandResult> {
        let ssh_config = client::Config::default();
        let config = Arc::new(ssh_config);

        let remote_tuple = format!("{}:{}", self.config.host, self.config.port);
        let mut session = retry(
            || async {
                let handler = Client::new(&self.config.host, self.config.port);

                tokio::time::timeout(
                    // Typical TCP retry interval is 1s, 2s, 4s, 8s, 16s, ...
                    time::Duration::from_secs(10),
                    russh::client::connect(
                        config.clone(),
                        (&self.config.host[..], self.config.port),
                        handler,
                    ),
                ).await?

            },
            "SSH connection to ",
            &remote_tuple,
        )
        .await
        .context("ssh connect/handshake")?;

        // Authenticate with password if provided, otherwise use the default key.
        let auth_result;
        if let Some(password) = self.config.password.as_deref() {
            auth_result = session
                .authenticate_password(&self.config.username, password)
                .await
                .context("auth")?;
        } else {
            // Load key from agent (also connects to the agent socket, so
            // acquire the same semaphore to avoid connection storms).
            let _agent_permit = agent_semaphore().acquire().await.unwrap();
            let stream = connect_agent().await.context("agent connect")?;
            let mut agent_client = keys::agent::client::AgentClient::connect(stream);

            let identities = agent_client
                .request_identities()
                .await
                .context("agent identities")?;
            for (i, identity) in identities.iter().enumerate() {
                log::debug!("Identity {}: {:?}", i, identity);
            }
            let id = first_identity(identities).context("agent identities")?;

            auth_result = session
                .authenticate_publickey_with(&self.config.username, id, None, &mut agent_client)
                .await
                .context("auth")?;

            drop(agent_client);
            drop(_agent_permit);
        }

        log::debug!("Authentication result: {:?}", auth_result);
        check_auth(&auth_result).context("auth")?;

        let mut channel = session
            .channel_open_session()
            .await
            .context("channel open")?;
        log::debug!("Channel opened");

        // XXX: is agent socket still connected at this point?

        channel
            .agent_forward(true)
            .await
            .context("agent forward request")?;
        channel.exec(true, command).await.context("exec")?;

        let mut outcome = OutcomeCollector::default();
        while let Some(msg) = channel.wait().await {
            outcome.feed(msg);
        }

        Ok(outcome.finish())
    }
}

// </russh> ///////////////////////////////////////////////////////////////

// <utils> ////////////////////////////////////////////////////////////////

// Coarse retry for whole connection attempts. For the narrow EAGAIN-on-connect
// case (sub-second, error-kind filtered) see retry_on_eagain() below.
async fn retry<T, F, Fut, E>(mut operation: F, op_name: &str, op_arg: &str) -> Result<T, E>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, E>>,
    E: std::fmt::Display,
{
    let delay_base_ms = 1000;
    let limit = 4;
    let mut attempt = 0;

    loop {
        attempt += 1;

        match operation().await {
            Ok(result) => return Ok(result),
            Err(e) => {
                // Fail fast if the operation is not retryable
                if e.to_string().contains("Unknown server key") {
                    log::error!("{op_name}{op_arg} failure: {e}");
                    return Err(e);
                }

                if attempt >= limit {
                    log::error!("{op_name}{op_arg} failure {attempt}/{limit}: {e}");
                    return Err(e);
                }

                // Quadratic backoff: 1s, 4s, 9s, ...
                let retry_delay_ms = delay_base_ms * (attempt * attempt);

                log::warn!(
                    "{op_name}{op_arg} error {attempt}/{limit}, will retry in {}s",
                    retry_delay_ms / 1000
                );

                tokio::time::sleep(time::Duration::from_millis(retry_delay_ms)).await;
            }
        }
    }
}

/// Retry an I/O operation that fails with EAGAIN/WouldBlock: 4 attempts,
/// backoff 200/400/800 ms with +-50% jitter so waiting sessions spread out.
/// Any other error is returned at once.
async fn retry_on_eagain<T, F, Fut>(what: &str, mut operation: F) -> std::io::Result<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = std::io::Result<T>>,
{
    let limit = 4;
    let mut attempt = 0;

    loop {
        attempt += 1;

        match operation().await {
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock && attempt < limit => {
                let delay = jittered(200 << (attempt - 1));
                log::warn!("{what} EAGAIN, retry {attempt}/{limit} in {}ms", delay.as_millis());
                tokio::time::sleep(delay).await;
            }
            result => return result,
        }
    }
}

/// base_ms +-50%. Each RandomState::new() gets different keys, so the delay
/// varies between calls; not cryptographic randomness.
fn jittered(base_ms: u64) -> time::Duration {
    use std::hash::{BuildHasher, Hasher};

    let random = std::collections::hash_map::RandomState::new()
        .build_hasher()
        .finish();
    time::Duration::from_millis(base_ms / 2 + random % (base_ms + 1))
}

// </utils> ///////////////////////////////////////////////////////////////

fn check_known_host(session: &ssh2::Session, host: &str) -> Result<(), std::io::Error> {
    let mut known_hosts = session.known_hosts().unwrap();

    // Initialize the known hosts with a global known hosts file
    let file = Path::new(&std::env::var("HOME").unwrap()).join(".ssh/known_hosts");
    known_hosts.read_file(&file, ssh2::KnownHostFileKind::OpenSSH)?;

    log::debug!("{} host key: {:?}", host, session.host_key().unwrap());

    // Check if the host is known
    let (key, _key_type) = session.host_key().unwrap();
    match known_hosts.check(host, key) {
        ssh2::CheckResult::Match => Ok(()),
        ssh2::CheckResult::NotFound => {
            log::error!("{} not found in known_hosts", host);
            Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "host not found in known_hosts",
            ))
        }
        ssh2::CheckResult::Mismatch => {
            log::error!("{} key mismatch in known_hosts", host);
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "host key mismatch in known_hosts",
            ))
        }
        ssh2::CheckResult::Failure => {
            log::error!("{} check failed", host);
            Err(std::io::Error::other("host check failed"))
        }
    }
}

#[derive(Debug, Clone)]
pub enum SshBackend {
    Russh,
    LibSsh2,
}

impl fmt::Display for SshBackend {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            SshBackend::Russh => write!(f, "russh"),
            SshBackend::LibSsh2 => write!(f, "libssh2"),
        }
    }
}

pub async fn execute(
    remote_host: &str,
    command: &str,
    remote_user: &str,
    backend: &SshBackend,
) -> (Option<String>, i32) {
    log::debug!(
        "Executing command '{}' on {}@{} using {}",
        command,
        remote_user,
        remote_host,
        backend
    );

    let server_config = ServerConfig {
        host: remote_host.to_string(),
        port: 22,
        username: remote_user.to_string(),
        password: None,
    };

    let result = match backend {
        SshBackend::Russh => {
            let executor = RusshExecutor {
                config: server_config.clone(),
            };
            executor.run_command(command).await
        }
        SshBackend::LibSsh2 => {
            let executor = LibSsh2Executor {
                config: server_config.clone(),
            };
            executor.run_command(command).await
        }
    };

    match result {
        Ok(res) => render_result(res),
        Err(e) => {
            // {:#} prints the whole chain: "agent connect: Resource temporarily unavailable"
            (Some(format!("{e:#}")), 1)
        }
    }
}

/// Output as printed (stdout, then stderr, then any failure line) and exit code.
fn render_result(res: CommandResult) -> (Option<String>, i32) {
    let combined = [&res.stdout[..], &res.stderr[..]].concat();
    let mut output = String::from_utf8_lossy(&combined).to_string();
    if let Some(failure) = res.failure {
        if !output.is_empty() && !output.ends_with('\n') {
            output.push('\n');
        }
        output.push_str(&failure);
    }
    (Some(output), res.exit_code as i32)
}

pub struct LibSsh2Executor {
    config: ServerConfig,
}

#[async_trait]
impl RemoteExecutor for LibSsh2Executor {
    async fn run_command(&self, command: &str) -> Result<CommandResult> {
        let remote_host = &self.config.host;
        let remote_user = &self.config.username;

        execute_libssh2(remote_host, command, remote_user).await
    }
}

// TODO: libssh2 backend is very slow under high parallelism because it uses
// blocking I/O (std::net::TcpStream, sess.handshake(), channel.read_to_string(), etc.)
// wrapped in async. This ties up tokio worker threads and serializes the work.
// Fix: wrap the entire function body in tokio::task::spawn_blocking().
pub async fn execute_libssh2(
    remote_host: &str,
    command: &str,
    remote_user: &str,
) -> Result<CommandResult> {
    let remote_port = "22";
    let remote_tuple = remote_host.to_owned() + ":" + remote_port;

    // Create a TCP connection to the remote host.
    let result = retry(
        || async {
            log::debug!("Attempting to connect to {}", remote_tuple);
            TcpStream::connect(&remote_tuple)
        },
        "TCP connection to ",
        remote_tuple.as_str(),
    )
    .await;

    let stream = match result {
        Ok(stream) => stream,
        Err(e) => {
            log::error!("Failed to connect to {}: {}", remote_tuple, e);
            return Err(e.into());
        }
    };

    // Create a new SSH session.
    let mut sess = match Session::new() {
        Ok(sess) => sess,
        Err(e) => {
            log::error!("Failed to create SSH session: {}", e);
            return Err(e.into());
        }
    };

    // Create a new SSH agent session.
    let agent_in = match sess.agent() {
        Ok(agent) => agent,
        Err(e) => {
            log::error!("Failed to create SSH agent session: {}", e);
            return Err(e.into());
        }
    };

    let agent_arc = Arc::new(Mutex::new(agent_in));

    // Connect to the agent and request a list of identities.
    let agent_identities = || async {
        let mut agent_clone = agent_arc.lock().await;
        agent_clone.connect().unwrap();
        match agent_clone.list_identities() {
            Ok(_) => Ok(()),
            Err(e) => {
                agent_clone.disconnect().unwrap();
                Err(e)
            }
        }
    };

    if let Err(e) = retry(agent_identities, "agent.list_identities() for ", remote_host).await {
        log::error!("Failed to list agent identities: {}", e);
        return Err(e.into());
    }

    // Associate the TCP stream with the SSH session; no error handling needed
    // here, any issues will manifest later.
    sess.set_tcp_stream(stream);

    // TODO: get the host key type from the known_hosts file and set it as preferred
    match sess.method_pref(ssh2::MethodType::HostKey, "ssh-ed25519") {
        Ok(_) => {}
        Err(e) => {
            log::error!("Failed to set preferred host key type: {}", e);
            return Err(e.into());
        }
    }

    // Attempt SSH handshake.
    // Maybe it's just me, but retries aren't playing nice (libssh2/rust bindings?).
    // Adopting a "fail fast, log, and sigh" approach for now.
    match sess.handshake() {
        Ok(_) => {}
        Err(e) => {
            log::error!("SSH handshake failure: {}", e);
            return Err(e.into());
        }
    }

    log::debug!(
        "SSH supported algorithms: {:?}",
        sess.supported_algs(ssh2::MethodType::HostKey)
    );
    log::debug!(
        "SSH active methods: {:?}",
        sess.methods(ssh2::MethodType::HostKey)
    );

    // Check the public key of the remote host.
    if check_known_host(&sess, remote_host).is_err() {
        return Err(
            std::io::Error::new(std::io::ErrorKind::InvalidData, "host key mismatch").into(),
        );
    }

    // Try to authenticate with the first identity in the agent.
    let mut agent_auth_success = false;
    let mut agent_auth_error: String = "".to_string();
    let mut agent_clone = agent_arc.lock().await;
    for identity in agent_clone.identities().unwrap() {
        match agent_clone.userauth(remote_user, &identity) {
            Ok(_) => {
                log::debug!("agent success for {}", identity.comment());
                agent_auth_success = true;
                agent_clone.disconnect().unwrap();
                break;
            }
            Err(error) => {
                agent_auth_error = error.message().to_owned();
                log::error!(
                    "agent failure for {}: {}",
                    identity.comment(),
                    agent_auth_error
                );
            }
        }
    }

    if !agent_auth_success {
        log::error!("fatal failure {} for {}", agent_auth_error, remote_host);
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "agent authentication failure",
        )
        .into());
    }

    // Create the SSH channel.
    let mut channel = sess.channel_session()?;
    // TODO: agent forwarding

    channel.handle_extended_data(ssh2::ExtendedData::Merge)?;

    // Execute command on the remote host.
    channel.exec(command)?;

    let mut out = String::new();
    channel.read_to_string(&mut out)?;

    channel.close()?;
    channel.wait_close()?;

    let exit_status = channel.exit_status()?;

    Ok(CommandResult {
        stdout: out.into_bytes(),
        stderr: Vec::new(),
        exit_code: exit_status as u32,
        failure: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing_log::LogTracer;
    use tracing_test::traced_test;

    #[tokio::test]
    #[traced_test]
    async fn test_retry() {
        let _ = LogTracer::init(); // Ignore if already initialized

        let result = retry(
            || async {
                log::info!("Attempting operation");
                Err::<(), _>(std::io::Error::other("failed"))
            },
            "op_test:",
            "op_arg",
        )
        .await;

        assert!(result.is_err());
        assert!(logs_contain("op_test:op_arg error 1/4, will retry in 1s"));
        assert!(logs_contain("op_test:op_arg error 2/4, will retry in 4s"));
        assert!(logs_contain("op_test:op_arg error 3/4, will retry in 9s"));
        assert!(logs_contain("op_test:op_arg failure 4/4: failed"));
    }

    /* retry_on_eagain() */

    use std::io::ErrorKind::{Other, WouldBlock};
    use std::sync::atomic::{AtomicUsize, Ordering};

    async fn count_attempts(fail_first: usize, kind: std::io::ErrorKind) -> (std::io::Result<()>, usize) {
        let attempts = AtomicUsize::new(0);
        let result = retry_on_eagain("test", || async {
            if attempts.fetch_add(1, Ordering::SeqCst) < fail_first {
                Err(std::io::Error::new(kind, "test"))
            } else {
                Ok(())
            }
        })
        .await;
        (result, attempts.load(Ordering::SeqCst))
    }

    #[tokio::test]
    async fn test_retry_on_eagain_recovers() {
        let (result, attempts) = count_attempts(2, WouldBlock).await;
        assert!(result.is_ok());
        assert_eq!(attempts, 3);
    }

    #[tokio::test]
    async fn test_retry_on_eagain_other_error_fails_at_once() {
        let (result, attempts) = count_attempts(usize::MAX, Other).await;
        assert_eq!(result.unwrap_err().kind(), Other);
        assert_eq!(attempts, 1);
    }

    #[tokio::test]
    async fn test_retry_on_eagain_gives_up() {
        let (result, attempts) = count_attempts(usize::MAX, WouldBlock).await;
        assert_eq!(result.unwrap_err().kind(), WouldBlock);
        assert_eq!(attempts, 4);
    }

    /// A real Unix socket whose accept queue is full returns EAGAIN on connect
    /// (the agent case); the retry must get through once the listener drains it.
    #[tokio::test]
    async fn test_retry_on_eagain_full_backlog() {
        use std::os::unix::io::AsRawFd;

        // A directory only this test owns (create_dir fails if the name exists);
        // the guard removes it on every exit, including a failed assertion.
        struct OwnedDir(std::path::PathBuf);
        impl Drop for OwnedDir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        // /tmp, not temp_dir(): a long $TMPDIR exceeds the 108-byte socket path limit.
        let dir_path = std::path::Path::new("/tmp")
            .join(format!("mpssh-test-{}-{}", std::process::id(), nanos));
        std::fs::create_dir(&dir_path).unwrap();
        let dir = OwnedDir(dir_path);
        let path = dir.0.join("agent.sock");
        let std_listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        // Calling listen() again on a listening socket sets a new backlog: 0 = one pending connection.
        assert_eq!(unsafe { libc::listen(std_listener.as_raw_fd(), 0) }, 0);
        std_listener.set_nonblocking(true).unwrap();
        let listener = tokio::net::UnixListener::from_std(std_listener).unwrap();

        // Fill the accept queue until connect fails with EAGAIN; keep those connections open.
        let mut queued = Vec::new();
        loop {
            match tokio::net::UnixStream::connect(&path).await {
                Ok(stream) => queued.push(stream),
                Err(e) if e.kind() == WouldBlock => break,
                Err(e) => panic!("unexpected connect error: {}", e),
            }
            assert!(queued.len() < 16, "backlog never filled: the test would not exercise the retry");
        }

        // Drain the queue only after the first attempt has failed.
        let acceptor = tokio::spawn(async move {
            tokio::time::sleep(time::Duration::from_millis(50)).await;
            let mut accepted = Vec::new();
            while let Ok((stream, _)) = listener.accept().await {
                accepted.push(stream);
            }
        });

        let attempts = AtomicUsize::new(0);
        let result = retry_on_eagain("test", || {
            attempts.fetch_add(1, Ordering::SeqCst);
            tokio::net::UnixStream::connect(&path)
        })
        .await;

        acceptor.abort();
        assert!(result.is_ok(), "connect failed: {:?}", result.err());
        assert!(attempts.load(Ordering::SeqCst) >= 2, "first attempt did not hit EAGAIN");
    }

    #[test]
    fn test_jittered_stays_within_half() {
        for _ in 0..1000 {
            let ms = jittered(200).as_millis();
            assert!((100..=300).contains(&ms), "{}", ms);
        }
    }

    /* OutcomeCollector */

    fn collect(msgs: Vec<ChannelMsg>) -> CommandResult {
        let mut outcome = OutcomeCollector::default();
        for msg in msgs {
            outcome.feed(msg);
        }
        outcome.finish()
    }

    fn data(bytes: &[u8]) -> ChannelMsg {
        ChannelMsg::Data { data: CryptoVec::from_slice(bytes) }
    }

    #[test]
    fn test_outcome_exit_zero_without_output_is_success() {
        let res = collect(vec![ChannelMsg::ExitStatus { exit_status: 0 }, ChannelMsg::Eof]);
        assert_eq!(res.exit_code, 0);
        assert!(res.failure.is_none());
        assert!(res.stdout.is_empty());
    }

    #[test]
    fn test_outcome_nonzero_exit_is_not_a_failure() {
        let res = collect(vec![data(b"out\n"), ChannelMsg::ExitStatus { exit_status: 3 }]);
        assert_eq!(res.exit_code, 3);
        assert!(res.failure.is_none());
    }

    #[test]
    fn test_outcome_no_exit_status_keeps_output() {
        let res = collect(vec![data(b"partial"), ChannelMsg::Eof, ChannelMsg::Close]);
        assert_eq!(res.exit_code, EXIT_CODE_NO_STATUS);
        assert_eq!(res.failure.as_deref(), Some("exec: channel closed without exit status"));
        assert_eq!(res.stdout, b"partial");
    }

    #[test]
    fn test_outcome_signal_keeps_output() {
        let res = collect(vec![
            ChannelMsg::ExtendedData { data: CryptoVec::from_slice(b"dying\n"), ext: 1 },
            ChannelMsg::ExitSignal {
                signal_name: Sig::TERM,
                core_dumped: false,
                error_message: String::new(),
                lang_tag: String::new(),
            },
        ]);
        assert_eq!(res.exit_code, EXIT_CODE_NO_STATUS);
        assert_eq!(res.failure.as_deref(), Some("exec: killed by signal TERM"));
        assert_eq!(res.stderr, b"dying\n");
    }

    #[test]
    fn test_outcome_custom_signal_with_message_keeps_output() {
        let res = collect(vec![
            data(b"busy\n"),
            ChannelMsg::ExitSignal {
                signal_name: Sig::Custom("XCPU".to_string()),
                core_dumped: false,
                error_message: "CPU time limit exceeded".to_string(),
                lang_tag: String::new(),
            },
        ]);
        assert_eq!(res.exit_code, EXIT_CODE_NO_STATUS);
        assert_eq!(
            res.failure.as_deref(),
            Some("exec: killed by signal XCPU (CPU time limit exceeded)")
        );
        assert_eq!(res.stdout, b"busy\n");
    }

    #[test]
    fn test_render_result_appends_failure_on_its_own_line() {
        let (output, code) = render_result(collect(vec![data(b"partial")]));
        assert_eq!(output.as_deref(), Some("partial\nexec: channel closed without exit status"));
        assert_eq!(code, 255);

        let (output, _) = render_result(collect(vec![]));
        assert_eq!(output.as_deref(), Some("exec: channel closed without exit status"));
    }

    /* login checks */

    #[test]
    fn test_check_auth_rejects_failure() {
        assert!(check_auth(&client::AuthResult::Success).is_ok());
        let rejected = client::AuthResult::Failure {
            remaining_methods: MethodSet::empty(),
            partial_success: false,
        };
        assert_eq!(check_auth(&rejected).unwrap_err().to_string(), "rejected by server");
    }

    #[test]
    fn test_first_identity_empty_agent_is_an_error() {
        assert_eq!(first_identity(vec![7, 8]).unwrap(), 7);
        assert_eq!(
            first_identity(Vec::<u8>::new()).unwrap_err().to_string(),
            "agent has no identities"
        );
    }
}
