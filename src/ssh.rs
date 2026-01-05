use ssh2::Session;
use std::fmt;
use std::io::Read;
use std::net::TcpStream;
use std::path::Path;
use std::time;

// <russh> ////////////////////////////////////////////////////////////////

use std::sync::Arc;

use async_trait::async_trait;

use anyhow::Result;
use byteorder::{BigEndian, ByteOrder};
use russh::*;
use russh_keys::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;

/* <ssh agent> */

const SSH_AGENT_SUCCESS: u8 = 5;
const SSH_AGENT_FAILURE: u8 = 6;
const SSH2_AGENTC_REQUEST_IDENTITIES: u8 = 11;
const SSH2_AGENT_IDENTITIES_ANSWER: u8 = 12;
const SSH2_AGENTC_SIGN_REQUEST: u8 = 13;
const SSH2_AGENT_SIGN_RESPONSE: u8 = 14;

fn parse_agent_message(data: &[u8]) {
    if data.len() < 4 {
        log::error!("Message too short");
        return;
    }

    // Parse the length prefix (first 4 bytes)
    let msg_len = BigEndian::read_u32(&data[0..4]);
    log::debug!("Message length: {}", msg_len);

    if data.len() < 5 {
        log::error!("No message type");
        log::error!("Message: {:?}", data);
        return;
    }

    // Get message type (5th byte)
    let msg_type = data[4];

    match msg_type {
        SSH_AGENT_SUCCESS => {
            log::debug!("Message type: SUCCESS");
        }
        SSH_AGENT_FAILURE => {
            log::debug!("Message type: FAILURE");
        }
        SSH2_AGENTC_REQUEST_IDENTITIES => {
            log::debug!("Message type: REQUEST_IDENTITIES");
        }
        SSH2_AGENT_IDENTITIES_ANSWER => {
            if data.len() < 9 {
                return;
            }
            let num_keys = BigEndian::read_u32(&data[5..9]);
            log::debug!("Message type: IDENTITIES_ANSWER");
            log::debug!("Number of keys: {}", num_keys);

            // Parse each key
            let mut pos = 9;
            for i in 0..num_keys {
                if pos + 4 > data.len() {
                    break;
                }

                // Read key blob length
                let blob_len = BigEndian::read_u32(&data[pos..pos + 4]) as usize;
                pos += 4;

                if pos + blob_len > data.len() {
                    break;
                }

                // Parse key blob
                let key_blob = &data[pos..pos + blob_len];
                if let Ok(key_type) = std::str::from_utf8(&key_blob[4..]) {
                    if let Some(end) = key_type.find('\0') {
                        log::debug!("Key {}: type {}", i, &key_type[..end]);
                    }
                }
                pos += blob_len;

                // Read comment length
                if pos + 4 > data.len() {
                    break;
                }
                let comment_len = BigEndian::read_u32(&data[pos..pos + 4]) as usize;
                pos += 4;

                if pos + comment_len > data.len() {
                    break;
                }

                // Parse comment
                if let Ok(comment) = std::str::from_utf8(&data[pos..pos + comment_len]) {
                    log::debug!("Key {} comment: {}", i, comment);
                }
                pos += comment_len;
            }
        }
        SSH2_AGENTC_SIGN_REQUEST => {
            log::debug!("Message type: SIGN_REQUEST");
        }
        SSH2_AGENT_SIGN_RESPONSE => {
            log::debug!("Message type: SIGN_RESPONSE");
        }
        _ => {
            log::debug!("Unknown message type: {}", msg_type);
        }
    }
}

async fn exchange_ssh_agent_message(data: &[u8]) -> std::io::Result<Vec<u8>> {
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

/* </ssh agent> */

/* <ssh client> */

struct Client {
    agent_channel: Option<ChannelId>,
    buffer: Mutex<Vec<u8>>,
    host: String,
    port: u16,
}

impl Client {
    pub fn new(host: &str, port: u16) -> Self {
        Self {
            agent_channel: None,
            buffer: Mutex::new(Vec::new()),
            host: host.to_string(),
            port,
        }
    }
}

#[async_trait]
impl client::Handler for Client {
    type Error = russh::Error;

    /// Callback to check the server's public key against a known_hosts file.
    async fn check_server_key(
        &mut self,
        server_public_key: &ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        let result = russh_keys::check_known_hosts(&self.host, self.port, server_public_key);
        log::debug!("check_server_key: {:?}", result);

        match result {
            Ok(true) => Ok(true),
            _ => Ok(false),
        }
    }

    /// Callback to handle an agent forwarding channel open request.
    async fn server_channel_open_agent_forward(
        &mut self,
        channel: russh::Channel<russh::client::Msg>,
        _session: &mut russh::client::Session,
    ) -> Result<(), Self::Error> {
        log::debug!("server_channel_open_agent_forward: {:?}", channel);
        self.agent_channel = Some(channel.id());
        Ok(())
    }

    /// Callback to handle (any) data received on a channel.
    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut russh::client::Session,
    ) -> Result<(), Self::Error> {
        log::debug!("data on channel: {}", channel);

        if let Some(agent_channel) = self.agent_channel {
            if agent_channel == channel {
                log::debug!("agent forward channel matched: {}", channel);

                // Acquire the buffer lock
                let mut buffer = self.buffer.lock().await;
                buffer.extend_from_slice(data);
                log::debug!("Buffer size after appending: {}", buffer.len());

                // Process complete messages
                while buffer.len() >= 4 {
                    // Read the length prefix
                    let msg_len = BigEndian::read_u32(&buffer[0..4]) as usize;

                    if buffer.len() < msg_len + 4 {
                        // Wait for more data...
                        break;
                    }

                    // Extract the message
                    let message = buffer[0..4 + msg_len].to_vec();
                    buffer.drain(0..4 + msg_len); // Remove the processed message from the buffer
                    log::debug!("Processing message of length: {}", msg_len);

                    // Print the message
                    parse_agent_message(&message);

                    // Forward the message to the agent
                    if let Ok(response) = exchange_ssh_agent_message(&message).await {
                        session.data(channel, russh::CryptoVec::from_slice(&response))?;
                    }
                }
            }
        }

        Ok(())
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
            // Load key from agent
            let agent_path = std::env::var("SSH_AUTH_SOCK").expect("SSH_AUTH_SOCK not set");
            let agent_stream = tokio::net::UnixStream::connect(&agent_path).await?;
            let mut agent_client = agent::client::AgentClient::connect(agent_stream);

            let identities = agent_client.request_identities().await?;
            for (i, identity) in identities.iter().enumerate() {
                log::debug!("Identity {}: {:?}", i, identity);
            }
            let id = identities.first().expect("No identities").clone();

            auth_result = session
                .authenticate_publickey_with(&self.config.username, id, &mut agent_client)
                .await?;

            drop(agent_client);
        }

        log::debug!("Authentication code: {}", auth_result);

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
    let mut channel = sess.channel_session().unwrap();
    // TODO: agent forwarding

    channel
        .handle_extended_data(ssh2::ExtendedData::Merge)
        .unwrap();

    // Execute command on the remote host.
    channel.exec(command).unwrap();

    let mut out = String::new();
    channel.read_to_string(&mut out).unwrap();

    channel.close().unwrap();
    channel.wait_close().unwrap();

    let exit_status = channel.exit_status().unwrap();

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
        LogTracer::init().expect("Failed to initialize LogTracer");

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
