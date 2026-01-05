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
 *  - Russh backend silently returns empty output (exit 0) on channel errors (e.g., very long commands)
 *  - Refactor print_output_with_tty() - 8 args is too many (clippy warning)
 *  - Remove or gate parse_agent_message() in ssh.rs - debug-only, unused for logic
 *  - Add support for ignoring errors / timeouts per host.
 *   - I.e. when we know some hosts are flaky: try them, but with shorter timeout and ignore
 *   errors? Mandatory end date, so we do not forgot some hosts like that forever. The alternative
 *   would be to exclude them from the host list, but this would be less convenient.
 *  - How to see which hosts are in progress now with async?
 *   - This was easy with threads (prctl::set_name()).
 *  - Progress ETA is not coping well with long tail distribution of slow hosts.
 *  - Add option to add host keys to known_hosts
 *  - Split stdout / stderr?
 *  - Support tail -f
 *  - -u mandatory?
 *  - File upload support?
 */

mod ssh;

use clap::{App, AppSettings, Arg};

use std::io::prelude::*;

use libc::getrlimit;
use prctl::set_name;
use std::mem::MaybeUninit;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::time;

use ansi_term::Colour;
use atty::Stream;
use std::fs::File;
use std::io::BufReader;

use tokio::sync::{mpsc, Semaphore};

use tracing_subscriber::{fmt, prelude::*, EnvFilter};

const VERSION: &str = "0.93.1";
const AUTHOR: &str = "Teodor Milkov <tm@del.bg>";

enum PrintThreadMsg {
    HostResult {
        host: String,
        output: Option<String>,
        exit_status: i32,
        elapsed: time::Duration,
        active_threads: usize,
    },
    Shutdown,
}

#[derive(Debug)]
struct CompletionTimes {
    durations: Vec<time::Duration>,
    last_update: time::Instant,
}

#[derive(Debug)]
pub struct ProgressTracker {
    hosts_total: usize,
    start_time: time::Instant,
    completion_times: CompletionTimes,
    active_threads: usize,
}

/// Calculate the progress of the parallel SSH execution.
impl ProgressTracker {
    pub fn new(hosts_total: usize) -> Self {
        Self {
            hosts_total,
            start_time: time::Instant::now(),
            completion_times: CompletionTimes {
                durations: Vec::new(),
                last_update: time::Instant::now(),
            },
            active_threads: 0,
        }
    }

    pub fn update_completion(&mut self, thread_elapsed: time::Duration) {
        self.completion_times.durations.push(thread_elapsed);
        self.completion_times.last_update = time::Instant::now();
    }

    pub fn update_active_threads(&mut self, count: usize) {
        self.active_threads = count;
    }

    pub fn calculate_wma_eta(&self, hosts_left: usize) -> f32 {
        let mut sum_weights = 0;
        let mut weighted_sum = time::Duration::ZERO;

        for (i, &time) in self.completion_times.durations.iter().enumerate() {
            let weight = (i + 1).pow(2) as u32;
            sum_weights += weight;
            weighted_sum += time * weight;
        }

        // This is to account for the case where there were no completions in
        // a while and the completion times are not representative of the current
        // rate (long tail distribution). Add a fake completion time for each
        // active thread.
        // FIXME: This does not sound right. Shouldn't we add just one fake?
        let last_completion_secs_ago = self.completion_times.last_update.elapsed().as_secs_f32();
        if last_completion_secs_ago > 2.0 {
            let fake_completion_times_count =
                self.completion_times.durations.len() + self.active_threads;
            for i in self.completion_times.durations.len()..fake_completion_times_count {
                let weight = (i + 1).pow(2) as u32;
                sum_weights += weight;
                weighted_sum += time::Duration::from_secs_f32(last_completion_secs_ago) * weight;
            }
        }

        let weighted_avg_time_per_thread = weighted_sum / sum_weights;
        (weighted_avg_time_per_thread.as_secs_f32() * hosts_left as f32)
            / self.active_threads as f32
    }

    pub fn calculate_progress(&self, hosts_left: usize) -> (usize, f32, String) {
        let updated_hosts_left = hosts_left;
        let hosts_left_pct = updated_hosts_left as f32 / self.hosts_total as f32 * 100.0;
        let elapsed_secs = self.start_time.elapsed().as_secs_f32();

        let eta_str: String = if hosts_left_pct <= 99.0 && elapsed_secs > 4.0 {
            let eta_wma = self.calculate_wma_eta(updated_hosts_left);
            let hosts_done = self.hosts_total - updated_hosts_left;
            let eta_avg_rate = updated_hosts_left as f32 / (hosts_done as f32 / elapsed_secs);
            let eta = (eta_wma + eta_avg_rate) / 2.0;
            let eta_m = eta as u32 / 60;
            let eta_s = eta % 60.0;

            format!(
                "{:02}m{:02.0}s({:2.1}|{:2.1})",
                eta_m, eta_s, eta_wma, eta_avg_rate
            )
        } else {
            "??m??s".to_string()
        };

        (updated_hosts_left, hosts_left_pct, eta_str)
    }
}

// Extract formatting to a testable function
pub fn format_output_line(
    host: &str,
    line: &str,
    exit_status: i32,
    host_max_width: usize,
    hosts_left_pct: f32,
    eta_str: &str,
    is_tty: bool,
) -> String {
    let delim_text = if exit_status == 0 { "->" } else { "=>" };
    let delim = if is_tty {
        let color = if exit_status == 0 {
            Colour::Fixed(10)
        } else {
            Colour::Fixed(9)
        };
        format!("{}", color.paint(delim_text))
    } else {
        delim_text.to_string()
    };

    // Pre-format the host part with consistent width
    let host_part = format!("{:<width$}", host, width = host_max_width);

    if !is_tty {
        // For non-tty stdout, use simplified output without progress info
        format!("{} {} {}", host_part, delim, line)
    } else {
        // For tty stdout, include progress information
        format!(
            "{} {:>4.1}%-{}{} {}",
            host_part, hosts_left_pct, eta_str, delim, line
        )
    }
}

pub fn print_output(
    host: &str,
    out: String,
    exit_status: i32,
    host_max_width: usize,
    hosts_left_pct: f32,
    eta_str: String,
) {
    // Use the existing function with atty::is(Stream::Stdout)
    print_output_with_tty(
        host,
        out,
        exit_status,
        host_max_width,
        hosts_left_pct,
        eta_str,
        atty::is(Stream::Stdout),
        atty::is(Stream::Stderr),
    )
}

// Separate function that allows injecting the TTY status
pub fn print_output_with_tty(
    host: &str,
    out: String,
    exit_status: i32,
    host_max_width: usize,
    hosts_left_pct: f32,
    eta_str: String,
    stdout_is_tty: bool,
    stderr_is_tty: bool,
) {
    let text: String = if out.is_empty() {
        if exit_status == 0 {
            // Only print progress to stderr if it's a tty
            if stderr_is_tty {
                eprint!("{:>4.1}% / {:>5}\r", hosts_left_pct, eta_str);
            }
            return;
        }
        "\n".to_string()
    } else {
        out
    };

    let stdout = std::io::stdout();
    let mut stdout_handle = stdout.lock();
    for line in text.lines() {
        // Update progress on stderr if it's a tty, even when stdout isn't
        if !stdout_is_tty && stderr_is_tty {
            eprint!("{:>4.1}% / {:>5}\r", hosts_left_pct, eta_str);
        }

        let output_line = format_output_line(
            host,
            line,
            exit_status,
            host_max_width,
            hosts_left_pct,
            &eta_str,
            stdout_is_tty,
        );

        if let Err(e) = writeln!(&mut stdout_handle, "{}", output_line) {
            log::error!("Failed to write to stdout: {}", e);
            panic!("Error writing to stdout: {}", e);
        }
    }
}

fn spawn_print_thread(
    mut rx: mpsc::Receiver<PrintThreadMsg>,
    write_to_file: bool,
    suppress_output: bool,
    hosts_total: usize,
    host_max_width: usize,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut progress_tracker = ProgressTracker::new(hosts_total);

        let mut hosts_left = hosts_total;
        let mut interval = tokio::time::interval(time::Duration::from_secs(1));

        loop {
            tokio::select! {
                msg = rx.recv() => {
                    match msg {
                        Some(PrintThreadMsg::Shutdown) => {
                            break;
                        }
                        Some(PrintThreadMsg::HostResult { host, mut output, exit_status, elapsed, active_threads }) => {

                        // Write to file if requested and there is output.
                        if write_to_file && output.is_some() {
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
                                if let Some(ref out) = output {
                                    if let Err(e) = file.write_all(out.as_bytes()) {
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
                            output.take();
                        }

                        progress_tracker.update_completion(elapsed);
                        progress_tracker.update_active_threads(active_threads);

                        let (hosts_left_updated, hosts_left_pct, eta_str) = progress_tracker.calculate_progress(
                            hosts_left - 1
                        );
                        hosts_left = hosts_left_updated;

                        // print_output() will panic if stdout is closed (e.g. piped to head)
                        print_output(
                            &host,
                            output.as_deref().unwrap_or("").to_string(),
                            exit_status,
                            host_max_width,
                            hosts_left_pct,
                            eta_str,
                        );
                    }
                    None => {
                        log::debug!("Channel closed");
                        break;
                    }
                } // match
            } // tokio::select

            _ = interval.tick() => {
                            // Handle periodic progress updates
                            let (hosts_left_updated, hosts_left_pct, eta_str) = progress_tracker.calculate_progress(
                                hosts_left
                            );
                            hosts_left = hosts_left_updated;

                            print_output(
                                "",            // Placeholder for host, since no new message was received
                                String::new(), // Placeholder for out
                                0,             // Placeholder for exit_status
                                host_max_width,
                                hosts_left_pct,
                                eta_str,
                            );
                        }
                    } // tokio::select
        } // loop
    }) // tokio::spawn
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

fn process_args(args: Option<Vec<&str>>) -> clap::ArgMatches<'static> {
    let matches = App::new("Mass parallel SSH in Rust")
        .version(VERSION)
        .author(AUTHOR)
        .about("\nExecutes an SSH command simultaneously on many hosts.")
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
        .arg(
            Arg::with_name("ssh_backend")
                .short("b")
                .long("ssh-backend")
                .takes_value(true)
                .possible_values(&["russh", "libssh2"])
                .default_value("russh")
                .help("SSH backend to use (russh, libssh2)"),
        )
        .arg(Arg::with_name("debug").takes_value(false).long("debug"));

    // If args are provided, call get_matches_from_safe() to avoid panics.
    if let Some(args) = args {
        // On error, print the error message and return an empty ArgMatches.
        matches
            .get_matches_from_safe(args)
            .expect("Error parsing arguments.")
    } else {
        matches.get_matches()
    }
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

#[derive(Debug, Clone)]
struct Config {
    hosts_list_file: String,
    parallel_sessions: usize,
    delay: u64,
    remote_command: String,
    remote_user: String,
    ssh_backend: ssh::SshBackend,
    write_to_file: bool,
    suppress_output: bool,
    debug: bool,
}

impl Config {
    fn from_args(matches: clap::ArgMatches) -> Self {
        let mut remote_user = matches.value_of("user").unwrap_or("").to_owned();

        if remote_user.is_empty() {
            remote_user = users::get_current_username()
                .expect("The current user does not exist!")
                .into_string()
                .unwrap();
        }

        let ssh_backend_raw = matches.value_of("ssh_backend").unwrap().to_owned();
        let ssh_backend = match ssh_backend_raw.as_str() {
            "russh" => ssh::SshBackend::Russh,
            "libssh2" => ssh::SshBackend::LibSsh2,
            _ => {
                log::error!("Unknown SSH backend: {}", ssh_backend_raw);
                std::process::exit(1);
            }
        };

        Self {
            hosts_list_file: matches.value_of("file").unwrap().to_owned(),
            parallel_sessions: matches
                .value_of("parallel")
                .unwrap()
                .parse::<usize>()
                .unwrap(),
            delay: matches.value_of("delay").unwrap().parse::<u64>().unwrap(),
            remote_command: matches.value_of("command").unwrap().to_owned(),
            remote_user,
            ssh_backend,
            write_to_file: matches.is_present("write_to_file"),
            suppress_output: matches.is_present("suppress_output"),
            debug: matches.is_present("debug"),
        }
    }
}

fn main() {
    let config = Config::from_args(process_args(None));

    let level = if config.debug {
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

    run(config);
}

#[tokio::main]
async fn run(config: Config) {
    let hosts_list_file = config.hosts_list_file;
    let parallel_sessions = config.parallel_sessions;
    let delay = config.delay;
    let remote_command = config.remote_command;
    let remote_user = config.remote_user;
    let ssh_backend = config.ssh_backend;

    if config.write_to_file {
        ensure_dir_is_clean_and_writable();
    }

    let hosts_list = get_hosts_list(&hosts_list_file);
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
    let (tx, rx) = tokio::sync::mpsc::channel::<PrintThreadMsg>(n_workers);

    let suppress_output = config.suppress_output;

    let host_max_width: usize = hosts_list
        .iter()
        .max_by(|x, y| x.len().cmp(&y.len()))
        .unwrap()
        .len();

    // Create the print thread.
    let print_thread = spawn_print_thread(
        rx,
        config.write_to_file,
        suppress_output,
        hosts_total,
        host_max_width,
    );

    let semaphore = Arc::new(Semaphore::new(n_workers));

    eprintln!("Mass parallel SSH in Rust (v{}), (c) {}", VERSION, AUTHOR);
    eprintln!(" * using {} backend", ssh_backend);
    eprintln!(" * {} hosts from the list", hosts_list.len());
    eprintln!(" * {} threads", n_workers);
    eprintln!(" * {} ms delay", delay);
    eprintln!(" * command: {}\n", remote_command);

    // XXX: There was a reason to maintain my own counter, instead of using the
    // pool's active_count(), but I can't remember it now.
    // TODO: Consider revisiting the logic to evaluate if pool.active_count()
    // could be sufficient now.
    let active_threads = Arc::new(AtomicUsize::new(0));

    let mut join_set = tokio::task::JoinSet::new();

    for host in hosts_list {
        let semaphore_clone = semaphore.clone();

        let command_clone = remote_command.clone();
        let active_threads_clone = active_threads.clone();
        let user_clone = remote_user.clone();
        let ssh_backend_clone = ssh_backend.clone();
        let tx_clone = tx.clone();

        tracing::debug!("semaphore permits: {}", semaphore.available_permits());

        join_set.spawn(async move {
            let mut thread_name = "mps: ".to_owned();
            thread_name.push_str(&host);
            set_name(&thread_name).unwrap();

            let _permit = semaphore_clone.acquire().await.unwrap();

            active_threads_clone.fetch_add(1, Ordering::SeqCst);

            let thread_start = std::time::Instant::now();

            let (out, exit_status) =
                ssh::execute(&host, &command_clone, &user_clone, &ssh_backend_clone).await;

            let thread_elapsed = thread_start.elapsed();

            // Send output to the print thread.
            match tx_clone
                .send(PrintThreadMsg::HostResult {
                    host: host.clone(),
                    output: out,
                    exit_status,
                    elapsed: thread_elapsed,
                    active_threads: active_threads_clone.load(Ordering::SeqCst),
                })
                .await
            {
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

            drop(_permit);
        }); // pool.execute()

        tokio::time::sleep(time::Duration::from_millis(delay)).await;
    } // for hosts_list

    while let Some(result) = join_set.join_next().await {
        result.unwrap();
    }

    // Tell the print thread to exit.
    tx.send(PrintThreadMsg::Shutdown).await.unwrap();
    drop(tx);

    print_thread.await.unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test config_from_args().

    #[test]
    fn test_config_from_args_basic() {
        let args = vec![
            "test",
            "--debug",
            "-s",
            "-w",
            "-u",
            "testor",
            "-f",
            "hosts.txt",
            "-p",
            "10",
            "-d",
            "20",
            "ls",
        ];

        let matches = process_args(Some(args));

        let config = Config::from_args(matches);

        assert!(config.debug, "debug");
        assert!(config.suppress_output, "suppress_output");
        assert!(config.write_to_file, "write_to_file");
        assert_eq!(config.remote_user, "testor");
        assert_eq!(config.hosts_list_file, "hosts.txt");
        assert_eq!(config.parallel_sessions, 10);
        assert_eq!(config.delay, 20);
        assert_eq!(config.remote_command, "ls");
    }

    #[test]
    fn test_config_from_args_default_values() {
        let matches = process_args(Some(vec!["test", "-f", "hosts.txt", "ls"]));

        let config = Config::from_args(matches);

        let current_user = users::get_current_username()
            .unwrap()
            .into_string()
            .unwrap();

        assert!(!config.write_to_file, "write_to_file");
        assert!(!config.suppress_output, "suppress_output");
        assert!(!config.debug, "debug");
        assert_eq!(config.remote_user, current_user);
        assert_eq!(config.parallel_sessions, 100);
        assert_eq!(config.delay, 10);
    }

    #[test]
    fn test_config_from_args_complex_command() {
        let args = vec![
            "test",
            "-f",
            "hosts.txt",
            "echo 'complex command' | grep command",
        ];

        let matches = process_args(Some(args));

        let config = Config::from_args(matches);

        assert_eq!(
            config.remote_command,
            "echo 'complex command' | grep command"
        );
    }

    #[test]
    fn test_config_from_args_missing_required_args() {
        let result = std::panic::catch_unwind(|| {
            process_args(Some(vec!["test"]));
        });

        assert!(result.is_err(), "Expected panic on missing required args");

        if let Err(e) = result {
            let msg = e.downcast_ref::<String>().unwrap();
            assert!(msg.contains("required arguments were not provided"));
        }
    }

    // Test the weighted moving average (WMA) calculation for ETA.

    #[test]
    fn test_calculate_wma_eta() {
        let mut progress_tracker = ProgressTracker::new(50);

        progress_tracker.update_completion(time::Duration::from_secs(1));
        progress_tracker.update_completion(time::Duration::from_secs(2));
        progress_tracker.update_completion(time::Duration::from_secs(3));

        progress_tracker.update_active_threads(10);

        let eta = progress_tracker.calculate_wma_eta(50);

        // With 3 samples of 1s, 2s, 3s
        // Weights: 1, 4, 9
        // sum_weights = 1 + 4 + 9 = 14
        // weighted_sum = 1 * 1 + 2 * 4 + 3 * 9 = 1 + 8 + 27 = 36
        // Expected weighted avg: 36/14 = 2.57s
        // Expected ETA = 2.57s * 50 hosts / 10 threads = 12.85s
        assert!((eta - 12.85).abs() < 0.1);
    }

    #[test]
    fn test_calculate_wma_eta_single_sample() {
        let mut progress_tracker = ProgressTracker::new(20);

        progress_tracker.update_completion(time::Duration::from_secs(2));
        progress_tracker.update_active_threads(5);

        let eta = progress_tracker.calculate_wma_eta(20);

        // With single 2s sample
        // Expected ETA = 2s * 20 hosts / 5 threads = 8s
        assert!((eta - 8.0).abs() < 0.1);
    }

    #[test]
    fn test_calculate_wma_eta_long_tail() {
        let mut progress_tracker = ProgressTracker::new(10);

        progress_tracker.update_completion(time::Duration::from_secs(1));
        progress_tracker.update_active_threads(2);

        // Sleep for a while to trigger long tail handling
        std::thread::sleep(time::Duration::from_secs(3));

        let eta = progress_tracker.calculate_wma_eta(10);

        // Should account for the delay in last completion
        // With 1 real sample of 1s and 2 (because of 2 active threads) fake samples of 3s
        // Weights: 1, 4, 9
        // sum_weights = 1 + 4 + 9 = 14
        // weighted_sum = 1 * 1 + 3 * 4 + 3 * 9 = 1 + 12 + 27 = 40
        // Expected weighted avg: 40/14 = 2.86s
        // Expected ETA = 2.86s * 10 hosts / 2 threads = 14.3s
        assert!((eta - 14.3).abs() < 0.1);
    }

    // Test the ProgressTracker::calculate_progress() method.

    #[test]
    fn test_calculate_progress_early_stage() {
        let mut progress_tracker = ProgressTracker::new(100);

        progress_tracker.update_completion(time::Duration::from_secs(1));
        progress_tracker.update_completion(time::Duration::from_secs(1));
        progress_tracker.update_completion(time::Duration::from_secs(1));

        progress_tracker.update_active_threads(1);

        let (left, pct, eta) = progress_tracker.calculate_progress(97);

        assert_eq!(left, 97);
        assert_eq!(pct, 97.0);
        assert_eq!(eta, "??m??s"); // Too early for ETA
    }

    #[test]
    fn test_calculate_progress_almost_done() {
        let mut progress_tracker = ProgressTracker::new(10);

        // Time calculation happens after at least 4s.
        for _ in 0..9 {
            progress_tracker.update_completion(time::Duration::from_secs(1));
            std::thread::sleep(std::time::Duration::from_millis(500));
        }

        progress_tracker.update_active_threads(1);

        let (left, pct, eta) = progress_tracker.calculate_progress(1);
        eprintln!("left: {}, pct: {}, eta: {}", left, pct, eta);

        assert_eq!(left, 1);
        assert_eq!(pct, 10.0);
        assert!(eta.starts_with("00m01s"));
    }

    // Test the spawn_print_thread() function.

    #[tokio::test]
    async fn test_spawn_print_thread_basic_output() {
        let (tx, rx) = mpsc::channel(1);

        let print_thread = spawn_print_thread(rx, false, false, 100, 10);

        tx.send(PrintThreadMsg::HostResult {
            host: "host".to_string(),
            output: Some("output".to_string()),
            exit_status: 0,
            elapsed: time::Duration::from_secs(1),
            active_threads: 1,
        })
        .await
        .unwrap();

        // Send the exit signal.
        tx.send(PrintThreadMsg::Shutdown).await.unwrap();

        print_thread.await.unwrap();
    }

    #[test]
    fn test_format_output_line_tty() {
        let host = "testhost";
        let line = "test output";
        let exit_status = 0;
        let host_max_width = 10;
        let hosts_left_pct = 50.0;
        let eta_str = "01m30s";
        let is_tty = true;

        let formatted = format_output_line(
            host,
            line,
            exit_status,
            host_max_width,
            hosts_left_pct,
            eta_str,
            is_tty,
        );

        // For TTY output, verify it contains progress information
        assert!(formatted.contains("50.0%"));
        assert!(formatted.contains("01m30s"));
        assert!(formatted.contains(host));
        assert!(formatted.contains(line));
    }

    #[test]
    fn test_format_output_line_non_tty() {
        let host = "testhost";
        let line = "test output";
        let exit_status = 0;
        let host_max_width = 10;
        let hosts_left_pct = 50.0;
        let eta_str = "01m30s";
        let is_tty = false;

        let formatted = format_output_line(
            host,
            line,
            exit_status,
            host_max_width,
            hosts_left_pct,
            eta_str,
            is_tty,
        );

        // For non-TTY output, verify it doesn't contain progress information
        assert!(!formatted.contains("50.0%"));
        assert!(!formatted.contains("01m30s"));
        assert!(formatted.contains(host));
        assert!(formatted.contains(line));
        assert!(formatted.contains("->"));

        // Verify format is simpler
        let expected = format!("{:<width$} -> {}", host, line, width = host_max_width);
        assert_eq!(formatted, expected);
    }

    #[test]
    fn test_format_output_line_error_status() {
        let host = "testhost";
        let line = "test output";
        let exit_status = 1; // Error status
        let host_max_width = 10;
        let hosts_left_pct = 50.0;
        let eta_str = "01m30s";
        let is_tty = false;

        let formatted = format_output_line(
            host,
            line,
            exit_status,
            host_max_width,
            hosts_left_pct,
            eta_str,
            is_tty,
        );

        // Verify error delimiter
        assert!(formatted.contains("=>"));
        assert!(!formatted.contains("->"));
    }
}
