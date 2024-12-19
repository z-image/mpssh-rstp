use ssh2::Session;
use std::io::Read;
use std::net::TcpStream;
use std::path::Path;
use std::thread;
use std::time;

fn retry<T, F, E>(mut operation: F, op_name: &str, op_arg: &str) -> Result<T, E>
where
    F: FnMut() -> Result<T, E>,
    E: std::fmt::Display,
{
    let delay_base_ms = 1000;
    let limit = 4;
    let mut attempt = 0;

    loop {
        attempt += 1;

        match operation() {
            Ok(result) => return Ok(result),
            Err(e) => {
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

                thread::sleep(time::Duration::from_millis(retry_delay_ms));
            }
        }
    }
}

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
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "host check failed",
            ))
        }
    }
}

pub fn execute(remote_host: &str, command: &str, remote_user: &str) -> (Option<String>, i32) {
    let remote_port = "22";
    let remote_addr = remote_host.to_owned() + ":" + remote_port;

    // Create a TCP connection to the remote host.
    let stream = match retry(
        || TcpStream::connect(&remote_addr),
        "TCP connection to ",
        remote_addr.as_str(),
    ) {
        Ok(stream) => stream,
        Err(_) => {
            return (None, 1);
        }
    };

    // Create a new SSH session.
    let mut sess = match Session::new() {
        Ok(sess) => sess,
        Err(e) => {
            log::error!("Failed to create SSH session: {}", e);
            return (None, 1);
        }
    };

    // Create a new SSH agent session.
    let mut agent = match sess.agent() {
        Ok(agent) => agent,
        Err(e) => {
            log::error!("Failed to create SSH agent session: {}", e);
            return (None, 1);
        }
    };

    // Connect to the agent and request a list of identities.
    let agent_identities = || {
        agent.connect().unwrap();
        match agent.list_identities() {
            Ok(_) => Ok(()),
            Err(e) => {
                agent.disconnect().unwrap();
                Err(e)
            }
        }
    };

    if let Err(e) = retry(
        agent_identities,
        "agent.list_identities() for ",
        remote_host,
    ) {
        log::error!("Failed to list agent identities: {}", e);
        return (None, 1);
    }

    // Associate the TCP stream with the SSH session; no error handling needed
    // here, any issues will manifest later.
    sess.set_tcp_stream(stream);

    // TODO: get the host key type from the known_hosts file and set it as preferred
    match sess.method_pref(ssh2::MethodType::HostKey, "ssh-ed25519") {
        Ok(_) => {}
        Err(e) => {
            log::error!("Failed to set preferred host key type: {}", e);
            return (None, 1);
        }
    }

    // Attempt SSH handshake.
    // Maybe it's just me, but retries aren't playing nice (libssh2/rust bindings?).
    // Adopting a "fail fast, log, and sigh" approach for now.
    match sess.handshake() {
        Ok(_) => {}
        Err(e) => {
            log::error!("SSH handshake failure: {}", e);
            return (None, 1);
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
        return (None, 1);
    }

    // Try to authenticate with the first identity in the agent.
    let mut agent_auth_success = false;
    let mut agent_auth_error: String = "".to_string();
    for identity in agent.identities().unwrap() {
        match agent.userauth(remote_user, &identity) {
            Ok(_) => {
                log::debug!("agent success for {}", identity.comment());
                agent_auth_success = true;
                agent.disconnect().unwrap();
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
        return (None, 1);
    }

    // Create the SSH channel.
    let mut channel = sess.channel_session().unwrap();
    // TODO: agent forwarding
    // channel.request_auth_agent_forwarding().unwrap();

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

    (Some(out), exit_status)
}
