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

const VERSION: &str = "0.93";
const AUTHOR: &str = "Teodor Milkov <tm@del.bg>";

const SIGNAL_THREAD_EXIT: i32 = 999;

struct CompletionTimes {
    durations: Vec<time::Duration>,
    last_update: time::Instant,
}

fn calculate_wma_eta(
    completion_times: &CompletionTimes,
    active_threads_count: usize,
    hosts_left: usize,
) -> f32 {
    let mut sum_weights = 0;
    let mut weighted_sum = std::time::Duration::ZERO;

    for (i, &time) in completion_times.durations.iter().enumerate() {
        // i starts from 0, but weight 0 doesn't make sense
        let weight = (i + 1).pow(2) as u32;
        sum_weights += weight;
        weighted_sum += time * weight;
    }

    // This is to account for the case where the last completion was a long time
    // ago and the completion times are not representative of the current rate
    // (long tail distribution). Add a fake completion time for each active
    // thread.
    // FIXME: This does not sound right. Shouldn't we add just one fake
    // completion time, instead of one per active thread?
    let last_completion_secs_ago = completion_times.last_update.elapsed().as_secs_f32();
    if last_completion_secs_ago > 2.0 {
        let fake_completion_times_count = completion_times.durations.len() + active_threads_count;
        for i in completion_times.durations.len()..fake_completion_times_count {
            let weight = (i + 1).pow(2) as u32;
            sum_weights += weight;
            weighted_sum += time::Duration::from_secs_f32(last_completion_secs_ago) * weight;
        }
    }

    let weighted_avg_time_per_thread = weighted_sum / sum_weights;
    tracing::debug!(
        "avg_time_per_thread {:?}, active_threads {}, hosts_left {}",
        weighted_avg_time_per_thread,
        active_threads_count,
        hosts_left
    );

    (weighted_avg_time_per_thread.as_secs_f32() * hosts_left as f32) / active_threads_count as f32
}

fn calculate_progress(
    hosts_total: usize,
    hosts_left: usize,
    start_time: std::time::SystemTime,
    completion_times: &CompletionTimes,
    active_threads_count: usize,
    hosts_processed: usize,
) -> (usize, f32, String) {
    let updated_hosts_left = hosts_left - hosts_processed;
    let hosts_left_pct = updated_hosts_left as f32 / hosts_total as f32 * 100.0;
    let elapsed_secs = start_time.elapsed().unwrap().as_secs() as f32;

    let eta_str: String = if hosts_left_pct <= 99.0 && elapsed_secs > 4.0 {
        let eta_wma = calculate_wma_eta(completion_times, active_threads_count, updated_hosts_left);
        let hosts_done = hosts_total - updated_hosts_left;
        let eta_avg_rate = updated_hosts_left as f32 / (hosts_done as f32 / elapsed_secs);
        let eta = (eta_wma + eta_avg_rate) / 2.0;
        // let eta = eta_wma;
        let eta_m = eta as u32 / 60;
        let eta_s = eta % 60.0;

        // Signify slope direction with one or more arrows, depending on
        // direction and magnitude (→, ⇗, ↑, ↑↑, ⇘, ↓, ↓↓).
        let slope_ratio = eta_wma / eta_avg_rate;
        let slope_direction = if slope_ratio > 1.5 {
            "↑↑"
        } else if slope_ratio > 1.25 {
            " ↑"
        } else if slope_ratio > 1.0 {
            " ⇗"
        } else if slope_ratio < 0.666 {
            "↓↓"
        } else if slope_ratio < 0.75 {
            "↓ "
        } else if slope_ratio < 0.8 {
            "⇘ "
        } else {
            "→ "
        };
        /*
                format!(
                    "{:02}m{:02.0}s({:2.1}|{:2.1}){}{}s",
                    eta_m, eta_s, eta_wma, eta_avg_rate, slope_direction, elapsed_secs
                )
        */
        format!(
            "{:02}m{:02.0}s({:2.1}|{:2.1})",
            eta_m, eta_s, eta_wma, eta_avg_rate
        )
    } else {
        "??m??s".to_string() // ;
    };

    (updated_hosts_left, hosts_left_pct, eta_str)
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
    mut rx: mpsc::Receiver<(String, Option<String>, i32, time::Duration, usize)>,
    write_to_file: bool,
    suppress_output: bool,
    hosts_total: usize,
    host_max_width: usize,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let start_time = std::time::SystemTime::now();
        let mut hosts_left = hosts_total;
        let mut completion_times = CompletionTimes {
            durations: Vec::new(),
            last_update: time::Instant::now(),
        };
        let mut active_threads_cache: usize = 0;

        let mut interval = tokio::time::interval(time::Duration::from_secs(1));

        loop {
            tokio::select! {
                msg = rx.recv() => {
                    match msg {
                        Some((host, mut out, exit_status, thread_elapsed, active_threads)) => {
                            active_threads_cache = active_threads;

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

                        completion_times.durations.push(thread_elapsed);
                        completion_times.last_update = time::Instant::now();

                        // Calculate progress and ETA by calling:
                        let (hosts_left_updated, hosts_left_pct, eta_str) = calculate_progress(
                            hosts_total,
                            hosts_left,
                            start_time,
                            &completion_times,
                            active_threads_cache,
                            1, // One new host processed
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
                    None => {
                        log::error!("Channel closed");
                        break;
                    }
                } // match
            } // tokio::select

            _ = interval.tick() => {
                            // Handle periodic progress updates here
                            // Calculate progress and print it even though no new message was received
                            let (hosts_left_updated, hosts_left_pct, eta_str) = calculate_progress(
                                hosts_total,
                                hosts_left,
                                start_time,
                                &completion_times,
                                // You might need to adjust the way active_threads is determined
                                // since it won't be updated directly by message processing in this case
                                active_threads_cache,
                                0, // No new hosts processed
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
    let mut remote_user = config.remote_user;

    if remote_user.is_empty() {
        remote_user = match users::get_current_username() {
            Some(username) => username.into_string().unwrap(),
            None => panic!("The current user does not exist!"),
        };
    }

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
    let (tx, rx) = tokio::sync::mpsc::channel::<(String, Option<String>, i32, time::Duration, usize)>(
        n_workers,
    );

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
                .send((
                    host.clone(),
                    out,
                    exit_status,
                    thread_elapsed,
                    active_threads_clone.load(Ordering::SeqCst),
                ))
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
    tx.send((
        "".to_string(),
        None,
        SIGNAL_THREAD_EXIT,
        time::Duration::from_secs(0),
        0,
    ))
    .await
    .unwrap();

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
        let completion_times = CompletionTimes {
            durations: vec![
                time::Duration::from_secs(1),
                time::Duration::from_secs(2),
                time::Duration::from_secs(3),
            ],
            last_update: time::Instant::now(),
        };

        let eta = calculate_wma_eta(&completion_times, 10, 50);

        // With 3 samples of 1s, 2s, 3s
        // Weights: 1,4,9
        // sum_weights = 1+4+9 = 14
        // weighted_sum = 1*1 + 2*4 + 3*9 = 1 + 8 + 27 = 36
        // Expected weighted avg: 36/14 = 2.57s
        // Expected ETA = 2.57s * 50 hosts / 10 threads = 12.85s
        assert!((eta - 12.85).abs() < 0.1);
    }

    #[test]
    fn test_calculate_wma_eta_long_tail() {
        let completion_times = CompletionTimes {
            durations: vec![time::Duration::from_secs(1)],
            last_update: time::Instant::now() - time::Duration::from_secs(5),
        };

        let eta = calculate_wma_eta(&completion_times, 2, 10);

        // Should account for 5s delay in last completion
        // With 1 real sample of 1s and 2 fake samples of 5s
        // Weights: 1,4,9
        // sum_weights = 1+4+9 = 14
        // weighted_sum = 1*1 + 5*4 + 5*9 = 1 + 20 + 45 = 66
        // Expected weighted avg: 66/14 = 4.71s
        // Expected ETA = 4.71s * 10 hosts / 2 threads = 23.55s
        assert!((eta - 23.55).abs() < 0.1);
    }

    #[test]
    fn test_calculate_wma_eta_single_sample() {
        let completion_times = CompletionTimes {
            durations: vec![time::Duration::from_secs(2)],
            last_update: time::Instant::now(),
        };

        let eta = calculate_wma_eta(&completion_times, 5, 20);

        // With single 2s sample
        // Expected ETA = 2s * 20 hosts / 5 threads = 8s
        assert!((eta - 8.0).abs() < 0.1);
    }

    // Test the progress calculation.

    #[test]
    fn test_calculate_progress_long_tail() {
        let hosts_total = 100;
        let hosts_left = 50;
        let start_time = std::time::SystemTime::now();

        // Create old completion time to trigger long tail handling
        let completion_times = CompletionTimes {
            durations: vec![time::Duration::from_secs(1)],
            last_update: time::Instant::now() - time::Duration::from_secs(3),
        };

        let (left, pct, eta) = calculate_progress(
            hosts_total,
            hosts_left,
            start_time,
            &completion_times,
            10,
            5,
        );

        assert_eq!(left, 45);
        assert!((pct - 45.0).abs() < 0.01);
        assert!(eta.contains("m") && eta.contains("s"));
    }

    #[test]
    fn test_calculate_progress_early_stage() {
        let start_time = std::time::SystemTime::now();
        let completion_times = CompletionTimes {
            durations: vec![
                time::Duration::from_secs(1),
                time::Duration::from_secs(1),
                time::Duration::from_secs(1),
            ],
            last_update: time::Instant::now(),
        };
        let (left, pct, eta) = calculate_progress(100, 99, start_time, &completion_times, 10, 1);

        assert_eq!(left, 98);
        assert_eq!(pct, 98.0);
        assert_eq!(eta, "??m??s"); // Too early for ETA
    }

    #[test]
    fn test_calculate_progress_almost_done() {
        let start_time = std::time::SystemTime::now() - std::time::Duration::from_secs(10);
        let completion_times = CompletionTimes {
            durations: vec![
                time::Duration::from_secs(1),
                time::Duration::from_secs(1),
                time::Duration::from_secs(1),
            ],
            last_update: time::Instant::now(),
        };

        let (left, pct, eta) = calculate_progress(100, 2, start_time, &completion_times, 2, 1);

        assert_eq!(left, 1);
        assert_eq!(pct, 1.0);
        assert!(eta.contains("m") && eta.contains("s"));
    }

    // Test the spawn_print_thread() function.

    #[tokio::test]
    async fn test_spawn_print_thread_basic_output() {
        let (tx, rx) = mpsc::channel(1);

        let print_thread = spawn_print_thread(rx, false, false, 100, 10);

        tx.send((
            "host".to_string(),
            Some("output".to_string()),
            0,
            time::Duration::from_secs(1),
            1,
        ))
        .await
        .unwrap();

        // Send the exit signal.
        tx.send((
            "".to_string(),
            None,
            SIGNAL_THREAD_EXIT,
            time::Duration::from_secs(0),
            0,
        ))
        .await
        .unwrap();

        print_thread.await.unwrap();
    }
}
