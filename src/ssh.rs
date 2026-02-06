use ssh2::Session;
use std::fmt;
use std::io::Read;
use std::net::TcpStream;
use std::path::Path;
use std::time;

// <russh> ////////////////////////////////////////////////////////////////

use std::sync::{Arc, OnceLock};

use anyhow::Result;
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

/// Exchange a message with the local SSH agent.
/// Acquires a semaphore permit to limit concurrent agent connections, and
/// retries on EAGAIN/WouldBlock with exponential backoff.
// NOTE: uses inline retry logic because the generic retry() helper doesn't
// support error-kind filtering or sub-second backoff. If more call sites need
// similar treatment, consider generalising retry() with a predicate + config.
async fn exchange_ssh_agent_message(data: &[u8]) -> std::io::Result<Vec<u8>> {
    let _permit = agent_semaphore().acquire().await.unwrap();

    let mut attempt = 0u32;
    let limit = 4;
    loop {
        attempt += 1;
        match exchange_ssh_agent_message_once(data).await {
            Ok(response) => return Ok(response),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock && attempt < limit => {
                let delay_ms = 200u64 * (1 << (attempt - 1)); // 200, 400, 800
                log::warn!(
                    "Agent socket EAGAIN, retry {attempt}/{limit} in {delay_ms}ms"
                );
                tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
            }
            Err(e) => return Err(e),
        }
    }
}

/// Send a single request to the SSH agent and read the complete response.
async fn exchange_ssh_agent_message_once(data: &[u8]) -> std::io::Result<Vec<u8>> {
    let path = std::env::var("SSH_AUTH_SOCK").expect("SSH_AUTH_SOCK not set");
    let mut stream = tokio::net::UnixStream::connect(path).await?;

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
        .await?;

        // Authenticate with password if provided, otherwise use the default key.
        let auth_result;
        if let Some(password) = self.config.password.as_deref() {
            auth_result = session
                .authenticate_password(&self.config.username, password)
                .await?;
        } else {
            // Load key from agent (also connects to the agent socket, so
            // acquire the same semaphore to avoid connection storms).
            let _agent_permit = agent_semaphore().acquire().await.unwrap();
            let mut agent_client = keys::agent::client::AgentClient::connect_env().await?;

            let identities = agent_client.request_identities().await?;
            for (i, identity) in identities.iter().enumerate() {
                log::debug!("Identity {}: {:?}", i, identity);
            }
            let id = identities.first().expect("No identities").clone();

            auth_result = session
                .authenticate_publickey_with(&self.config.username, id, None, &mut agent_client)
                .await?;

            drop(agent_client);
            drop(_agent_permit);
        }

        log::debug!("Authentication result: {:?}", auth_result);

        let mut channel = session.channel_open_session().await?;
        log::debug!("Channel opened");

        // XXX: is agent socket still connected at this point?

        channel.agent_forward(true).await?;
        channel.exec(true, command).await?;

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut exit_code = 0;

        while let Some(msg) = channel.wait().await {
            match msg {
                russh::ChannelMsg::Data { data } => stdout.extend_from_slice(&data),
                russh::ChannelMsg::ExtendedData { data, .. } => stderr.extend_from_slice(&data),
                russh::ChannelMsg::ExitStatus { exit_status } => exit_code = exit_status,
                _ => (),
            }
        }

        Ok(CommandResult {
            stdout,
            stderr,
            exit_code,
        })
    }
}

// </russh> ///////////////////////////////////////////////////////////////

// <utils> ////////////////////////////////////////////////////////////////

// NOTE: if more call sites need custom retry behaviour (e.g. error-kind
// filtering, sub-second backoff), consider adding a predicate + config to
// this helper instead of inlining retry loops elsewhere.
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
        Ok(res) => {
            let combined = [&res.stdout[..], &res.stderr[..]].concat();
            let output_str = String::from_utf8_lossy(&combined).to_string();
            (Some(output_str), res.exit_code as i32)
        }
        Err(e) => {
            (Some(e.to_string()), 1)
        }
    }
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
                Err::<(), _>(std::io::Error::new(std::io::ErrorKind::Other, "failed"))
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
}
