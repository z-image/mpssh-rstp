/*
 * Mass parallel SSH in Rust
 * (c) 2020 Teodor Milkov <tm@lifepattern.org>
 *
 * License: MPL-2.0
 * https://www.mozilla.org/en-US/MPL/2.0/
 *
 * See --help for usage.
 *
 * TODO:
 *  - Progress ETA is not coping well with long tail distribution of slow hosts.
 *  - Add option to add host keys to known_hosts
 *  - Split stdout / stderr?
 *  - auth agent forwarding
 *   - maybe switch to russh?
 *    - see server_channel_open_agent_forward() handler
 *  - support tail -f
 *  - -u mandatory?
 */

use clap::{App, AppSettings, Arg};

use ssh2::Session;
use std::net::TcpStream;

use std::io::prelude::*;

use libc::getrlimit;
use prctl::set_name;
use std::mem::MaybeUninit;
use std::path::Path;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    mpsc, Arc,
};
use std::thread;
use std::time;
use threadpool::ThreadPool;

use ansi_term::Colour;
use atty::Stream;
use std::fs::File;
use std::io::BufReader;

use tracing_subscriber::{fmt, prelude::*, EnvFilter};

const VERSION: &str = "0.93";
const AUTHOR: &str = "Teodor Milkov <tm@del.bg>";

const SIGNAL_THREAD_EXIT: i32 = 999;

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
    known_hosts
        .read_file(&file, ssh2::KnownHostFileKind::OpenSSH)
        .unwrap();

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

fn execute(remote_host: &str, command: &str, remote_user: &str) -> (Option<String>, i32) {
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
    let mut sess = Session::new().unwrap();

    // Create a new SSH agent session.
    let mut agent = sess.agent().unwrap();

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
    retry(
        agent_identities,
        "agent.list_identities() for ",
        remote_host,
    )
    .unwrap();

    // Attach the TCP stream to the SSH session.
    sess.set_tcp_stream(stream);

    // TODO: get the host key type from the known_hosts file and set it as preferred
    sess.method_pref(ssh2::MethodType::HostKey, "ssh-ed25519")
        .unwrap();

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

fn calculate_progress(
    hosts_total: usize,
    mut hosts_left: usize,
    start_time: std::time::SystemTime,
    completion_times: &[std::time::Duration],
    active_threads_count: usize,
) -> (usize, f32, String) {
    hosts_left -= 1;

    let hosts_left_pct = hosts_left as f32 / hosts_total as f32 * 100.0;
    let elapsed_secs = start_time.elapsed().unwrap().as_secs() as f32;

    let mut sum_weights = 1;

    let mut weighted_sum = std::time::Duration::ZERO;
    for (i, &time) in completion_times.iter().enumerate() {
        let weight = (i.pow(2)) as u32;
        sum_weights += weight;
        weighted_sum += time * weight;
    }

    let avg_time_per_thread = weighted_sum / sum_weights;
    tracing::debug!(
        "avg_time_per_thread {:?}, active_threads {}, hosts_left {}",
        avg_time_per_thread,
        active_threads_count,
        hosts_left
    );

    let eta_str: String = if hosts_left_pct <= 99.0 && elapsed_secs > 4.0 {
        let eta_wma =
            (avg_time_per_thread.as_secs_f32() * hosts_left as f32) / active_threads_count as f32;
        let eta_div = hosts_left as f32 / ((hosts_total - hosts_left) as f32 / elapsed_secs);
        let eta = (eta_wma + eta_div) / 2.0;
        let eta_m = eta as u32 / 60;
        let eta_s = eta % 60.0;

        // format!("{:02}m{:02.0}s({:2.1}|{:2.1})", eta_m, eta_s, eta_wma, eta_div)
        format!("{:02}m{:02.0}s", eta_m, eta_s) // ;
    } else {
        "??m??s".to_string() // ;
    };

    (hosts_left, hosts_left_pct, eta_str)
}

fn print_output(
    host: &str,
    out: String,
    exit_status: i32,
    host_max_width: usize,
    hosts_left_pct: f32,
    eta_str: String,
) {
    let text: String = if out.is_empty() {
        if exit_status == 0 {
            // this code is duplicated bellow
            eprint!("{:>4.1}% / {:>5}\r", hosts_left_pct, eta_str);
            return;
        }
        "\n".to_string() // ;
    } else {
        out // ;
    };

    let delim_text;
    let delim_ansi;
    if exit_status == 0 {
        delim_text = "->";
        delim_ansi = Colour::Fixed(10).paint(delim_text);
    } else {
        delim_text = "=>";
        delim_ansi = Colour::Fixed(9).paint(delim_text);
    }

    let delim = if atty::is(Stream::Stdout) {
        format!("{}", delim_ansi) // ;
    } else {
        delim_text.to_string() // ;
    };

    let stdout = std::io::stdout();
    let mut stdout_handle = stdout.lock();
    for line in text.lines() {
        if !atty::is(Stream::Stdout) && atty::is(Stream::Stderr) {
            // this code is duplicated above
            eprint!("{:>4.1}% / {:>5}\r", hosts_left_pct, eta_str);
        }
        let write_result = writeln!(
            &mut stdout_handle,
            "{:width$} {:>4.1}%-{:>5}{} {}",
            host,
            hosts_left_pct,
            eta_str,
            delim,
            line,
            width = host_max_width
        );

        if let Err(e) = write_result {
            log::error!("Failed to write to stdout: {}", e);
            panic!("Error writing to stdout: {}", e);
        }
    }
}

fn spawn_print_thread(
    rx: mpsc::Receiver<(String, Option<String>, i32, time::Duration, usize)>,
    write_to_file: bool,
    suppress_output: bool,
    hosts_total: usize,
    host_max_width: usize,
) -> thread::JoinHandle<()> {
    let print_thread = thread::spawn(move || {
        let start_time = std::time::SystemTime::now();
        let mut hosts_left = hosts_total;
        let mut completion_times = Vec::<std::time::Duration>::new();

        loop {
            match rx.recv() {
                Ok(msg) => {
                    let (host, mut out, exit_status, thread_elapsed, active_threads) = msg;

                    // Exit if the print thread receives the exit code from the
                    // main thread. This is a hack, but exiting is the only
                    // signal we currently need. May create a dedicated messaing
                    // argument or channel if needed in the future.
                    if exit_status == SIGNAL_THREAD_EXIT {
                        break;
                    }

                    // Write to file if requested and there is output.
                    if write_to_file && out.is_some() {
                        let filename = format!("mpssh-{}.out", host);

                        // Currently all of hosts' output is buffered in memory,
                        // so no need to append later.

                        // Bail out if the file already exists. Checking existence is racey,
                        // so we just try to open it and fail if it exists.
                        let mut file = match File::create(&filename) {
                            Ok(file) => file,
                            Err(e) => {
                                log::error!("Failed to create file {}: {}", filename, e);
                                continue;
                            }
                        };

                        // Write to file and sync to disk. File is closed on drop (end of scope).
                        {
                            if let Some(ref output) = out {
                                if let Err(e) = file.write_all(output.as_bytes()) {
                                    log::error!("Failed to write to file {}: {}", filename, e);
                                }
                            }

                            if let Err(e) = file.sync_all() {
                                log::error!("Failed to sync file {}: {}", filename, e);
                            }
                        }
                    }

                    // Clear the output, so it's not printed to stdout, but
                    // still sent to the print thread, so it can print progress.
                    if suppress_output {
                        out.take();
                    }

                    completion_times.push(thread_elapsed);

                    // Calculate progress and ETA by calling:
                    let (hosts_left_updated, hosts_left_pct, eta_str) = calculate_progress(
                        hosts_total,
                        hosts_left,
                        start_time,
                        &completion_times,
                        active_threads,
                    );
                    hosts_left = hosts_left_updated;

                    // print_output() will panic if stdout is closed (e.g. piped to head)
                    print_output(
                        &host,
                        out.as_deref().unwrap_or("").to_string(),
                        exit_status,
                        host_max_width,
                        hosts_left_pct,
                        eta_str,
                    );
                }

                Err(e) => {
                    log::error!("Error receiving from channel: {}", e);
                }
            }
        }
    });

    print_thread
}

fn get_hosts_list(filename: &str) -> Vec<String> {
    let mut hosts_list = Vec::new();

    let file = File::open(filename).unwrap();
    let file = BufReader::new(file);

    for line in file.lines() {
        let line_str = line.unwrap().trim().to_owned();
        if line_str.is_empty() {
            continue;
        }
        if line_str.starts_with('#') {
            continue;
        }
        hosts_list.push(line_str);
    }

    hosts_list
}

fn process_args() -> clap::ArgMatches<'static> {
    let matches = App::new("Mass parallel SSH in Rust")
        .version(VERSION)
        .author(AUTHOR)
        .about("\nExecutes an SSH command simulatenously on many hosts.")
        .setting(AppSettings::AllowExternalSubcommands)
        .setting(AppSettings::AllArgsOverrideSelf)
        .arg(
            Arg::with_name("file")
                .short("f")
                .long("file")
                .takes_value(true)
                .required(true)
                .help("file with hosts: one per line"),
        )
        .arg(
            Arg::with_name("user")
                .short("u")
                .long("user")
                .takes_value(true)
                .help("force SSH login as this username, instead of current user)"),
        )
        .arg(
            Arg::with_name("parallel")
                .short("p")
                .long("parallel")
                .takes_value(true)
                .default_value("100")
                .help("number of parallel SSH sessions"),
        )
        .arg(
            Arg::with_name("delay")
                .short("d")
                .long("delay")
                .takes_value(true)
                .default_value("10")
                .help("delay between each SSH session in milliseconds (ms)"),
        )
        .arg(
            Arg::with_name("suppress_output")
                .short("s")
                .long("suppress-output")
                .takes_value(false)
                .help("Suppress output from the remote command (only show progress)"),
        )
        .arg(
            Arg::with_name("write_to_file")
                .short("w")
                .long("write-to-file")
                .takes_value(false)
                .help("Write output to files, one per host"),
        )
        .arg(Arg::with_name("command").takes_value(true).required(true))
        .arg(Arg::with_name("debug").takes_value(false).long("debug"))
        .get_matches();

    matches
}

fn get_rlim_nofiles() -> usize {
    unsafe {
        let mut rl = MaybeUninit::<libc::rlimit>::uninit();
        getrlimit(libc::RLIMIT_NOFILE, rl.as_mut_ptr());
        rl.assume_init().rlim_cur as usize // ;
    } // ;
}

fn ensure_dir_is_clean_and_writable() {
    // No files starting with mpssh-* should exist in the current directory.
    // This is racey, but we just don't want to start the program at all if
    // there are files starting with mpssh-*. Will fail later if we can't create.
    for entry in std::fs::read_dir(".").unwrap() {
        let filename = entry.unwrap().file_name().into_string().unwrap();
        if filename.starts_with("mpssh-") {
            log::error!("Files mpssh-* already exist in the current directory.");
            std::process::exit(1);
        }
    }

    // Ensure we can write to the current directory.
    let test_filename = "mpssh-test-file";
    let mut file = File::create(test_filename).unwrap();
    file.write_all(b"test").unwrap();
    std::fs::remove_file(test_filename).unwrap();
}

fn main() {
    let matches = process_args();

    let level = if matches.is_present("debug") {
        String::from("debug")
    } else {
        std::env::var("RUST_LOG").unwrap_or_else(|_| String::from("info"))
    };

    let filter = EnvFilter::try_new(level).unwrap_or_else(|e| {
        eprintln!("Error parsing RUST_LOG: {}", e);
        std::process::exit(1);
    });

    let is_terminal = atty::is(Stream::Stdout) && atty::is(Stream::Stderr);

    tracing_subscriber::registry()
        .with(
            fmt::layer()
                .with_ansi(is_terminal)
                .with_writer(std::io::stderr),
        )
        .with(filter)
        .init();

    let hosts_list_file = matches.value_of("file").unwrap();
    let parallel_sessions = matches
        .value_of("parallel")
        .unwrap()
        .parse::<usize>()
        .unwrap();
    let delay = matches.value_of("delay").unwrap().parse::<u64>().unwrap();
    let remote_command = matches.value_of("command").unwrap().to_owned();
    let mut remote_user = matches.value_of("user").unwrap().to_owned();

    if remote_user.is_empty() {
        remote_user = match users::get_current_username() {
            Some(username) => username.into_string().unwrap(),
            None => panic!("The current user does not exist!"),
        };
    }

    let write_to_file = matches.is_present("write_to_file");
    if write_to_file {
        ensure_dir_is_clean_and_writable();
    }

    let hosts_list = get_hosts_list(hosts_list_file);
    let hosts_total = hosts_list.len();

    // Terminate early if there are no hosts.
    if hosts_total == 0 {
        log::error!("No hosts in the list.");
        std::process::exit(1);
    }

    let n_workers = std::cmp::min(parallel_sessions, hosts_total);

    // Each worker consumer 2 fds: 1 for ssh tcp + 1 for auth agent socket
    let rlim_nofiles = get_rlim_nofiles();
    if rlim_nofiles <= (n_workers * 2 + 14) {
        log::error!(
            "Requested parallelism of {} needs more fds than the allowed {}.",
            n_workers,
            rlim_nofiles
        );
        std::process::exit(1);
    }

    // Create a channel for communication with the print thread.
    let (tx, rx) = mpsc::channel::<(String, Option<String>, i32, time::Duration, usize)>();

    let suppress_output = matches.is_present("suppress_output");

    let host_max_width: usize = hosts_list
        .iter()
        .max_by(|x, y| x.len().cmp(&y.len()))
        .unwrap()
        .len();

    // Create the print thread.
    let print_thread = spawn_print_thread(
        rx,
        write_to_file,
        suppress_output,
        hosts_total,
        host_max_width,
    );

    let pool = ThreadPool::new(n_workers);

    eprintln!("Mass parallel SSH in Rust (v{}), (c) {}", VERSION, AUTHOR);
    eprintln!(" * {} hosts from the list", hosts_list.len());
    eprintln!(" * {} threads", n_workers);
    eprintln!(" * {} ms delay", delay);
    eprintln!(" * command: {}\n", remote_command);

    // XXX: There was a reason to maintain my own counter, instead of using the
    // pool's active_count(), but I can't remember it now.
    // TODO: Consider revisiting the logic to evaluate if pool.active_count()
    // could be sufficient now.
    let active_threads = Arc::new(AtomicUsize::new(0));

    for host in hosts_list {
        let command_clone = remote_command.clone();
        let active_threads_clone = active_threads.clone();
        let user_clone = remote_user.clone();
        let tx_clone = tx.clone();

        tracing::debug!("active_count {}", pool.active_count());
        pool.execute(move || {
            let mut thread_name = "mps: ".to_owned();
            thread_name.push_str(&host);
            set_name(&thread_name).unwrap();

            active_threads_clone.fetch_add(1, Ordering::SeqCst);

            let thread_start = std::time::Instant::now();
            let (out, exit_status) = execute(&host, &command_clone, &user_clone); // SSH
            let thread_elapsed = thread_start.elapsed();

            // Send output to the print thread.
            match tx_clone.send((
                host.clone(),
                out,
                exit_status,
                thread_elapsed,
                active_threads_clone.load(Ordering::SeqCst),
            )) {
                Ok(_) => {
                    log::debug!("Sent to print thread: {}", host);
                }
                Err(e) => {
                    log::error!("Failed to send to print thread: {}", e);
                    panic!("Failed to send to print thread: {}", e);
                }
            };

            thread_name = "mps: idle".to_owned();
            set_name(&thread_name).unwrap();

            active_threads_clone.fetch_sub(1, Ordering::SeqCst);
        });

        thread::sleep(time::Duration::from_millis(delay));
    }

    pool.join();

    // Tell the print thread to exit.
    tx.send((
        "".to_string(),
        None,
        SIGNAL_THREAD_EXIT,
        time::Duration::from_secs(0),
        0,
    ))
    .unwrap();

    print_thread.join().unwrap();
}
