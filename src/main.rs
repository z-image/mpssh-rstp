/*
 * TODO:
 *  - Description here
 *
 *  - Split stdout / stderr?
 *  - auth agent forwarding
 *   - maybe switch to russh?
 *  - support tail -f
 *  - -u mandatory?
 */

use clap::{Arg, App, AppSettings};

use std::net::TcpStream;
use ssh2::Session;

use std::io::prelude::*;

use std::thread;
use threadpool::ThreadPool;
use prctl::set_name;
use std::time;
use libc::getrlimit;
use std::mem::MaybeUninit;
use std::sync::{Arc, RwLock};

use std::fs::File;
use std::io::BufReader;
use ansi_term::Colour;
use atty::Stream;


const VERSION: &str = "0.7";
const AUTHOR: &str = "Teodor Milkov <tm@del.bg>";


fn execute(remote_host: &str, command: &str, remote_user: &str) -> (String, i32) {
    let remote_port = "22";
    let remote_addr = remote_host.to_owned() + ":" + remote_port;

    let stream;
    let mut retr: u64 = 0;
    let retr_limit = 3;
    loop {
        retr += 1;
        let retr_time = retr.pow(2) * 1000;
        stream = match TcpStream::connect(&remote_addr) {
            Ok(stream) => stream,
            Err(e) => {
                eprintln!("Connection retry {}/{} for {} in {} ms", retr, retr_limit, remote_host, retr_time);
                thread::sleep(time::Duration::from_millis(retr_time));
                if retr < retr_limit {
                    continue;
                }

                panic!("Connection ERROR: {:#?}", e);
            }
        };
        break;
    }
    let mut sess = Session::new().unwrap();

    let mut agent = sess.agent().unwrap();
    agent.connect().unwrap();
    agent.list_identities().unwrap();

    sess.set_tcp_stream(stream);
    sess.handshake().unwrap();

    let mut agent_auth_success = false;
    let mut agent_auth_error: String = "".to_string();
    for identity in agent.identities().unwrap() {
        match agent.userauth(remote_user, &identity) {
            Ok(_) => {
                agent_auth_success = true;
                break;
            },
            Err(error) => {
                // eprintln!("DEBUG: {}", error);
                agent_auth_error = error.message().to_owned();
            }
        }
    }

    if agent_auth_success == false {
        eprintln!("FATAL: {}", agent_auth_error);
        std::process::exit(1);
    }

    let mut channel = sess.channel_session().unwrap();
    // channel.request_auth_agent_forwarding().unwrap();

    channel.handle_extended_data(ssh2::ExtendedData::Merge).unwrap();
    channel.exec(command).unwrap();

    let mut out = String::new();
    channel.read_to_string(&mut out).unwrap();

    channel.close().unwrap();
    channel.wait_close().unwrap();

    let exit_status = channel.exit_status().unwrap();

    (out, exit_status)
}

fn calculate_progress(hosts_total: usize, hosts_left_lock: Arc::<RwLock::<usize>>, start_time: std::time::SystemTime) -> (f32, String) {
    let mut hosts_left = hosts_left_lock.write().unwrap();
    *hosts_left -= 1;
    let hosts_left_pct = *hosts_left as f32 / hosts_total as f32 * 100.0;
    let elapsed_secs = start_time.elapsed().unwrap().as_secs() as f32;

    let eta_str: String;
    if hosts_left_pct <= 99.0 && elapsed_secs > 4.0 {
        let eta = ((elapsed_secs / (100.0 as f32 - hosts_left_pct) * 100.0) - elapsed_secs) as usize;
        let eta_m = eta / 60;
        let eta_s = eta % 60;
        eta_str = format!("{:02}m{:02}s", eta_m, eta_s);
    } else {
        eta_str = "??m??s".to_string();
    }

    (hosts_left_pct, eta_str)
}

fn print_output(host: &str, out: String, exit_status: i32, host_max_width: usize, hosts_left_pct: f32, eta_str: String) {
    let text: String;

    if out.is_empty() {
        if exit_status == 0 {
            // code duplicated bellow
            eprint!("{:>4.1}% / {:>5}\r", hosts_left_pct, eta_str);
            std::io::stderr().flush().unwrap();
            return;
        }
        text = "\n".to_string();
    } else {
        text = out;
    }

    let delim_text;
    let delim_ansi;
    if exit_status == 0 {
        delim_text = "->";
        delim_ansi = Colour::Fixed(10).paint(delim_text);
    } else {
        delim_text = "=>";
        delim_ansi = Colour::Fixed(9).paint(delim_text);
    }

    let delim;
    if atty::is(Stream::Stdout) {
        delim = format!("{}", delim_ansi);
    } else {
        delim = delim_text.to_string();
    }

    let stdout = std::io::stdout();
    let mut stdout_handle = stdout.lock();
    for line in text.lines() {
        if !atty::is(Stream::Stdout) && atty::is(Stream::Stderr) {
            // code duplicated above
            eprint!("{:>4.1}% / {:>5}\r", hosts_left_pct, eta_str);
            std::io::stderr().flush().unwrap();
        }
        writeln!(&mut stdout_handle, "{:width$} {:>4.1}%-{:>5}{} {}", host, hosts_left_pct, eta_str, delim, line, width=host_max_width).unwrap();
    }
}

fn get_hosts_list(filename: &str) -> Vec<String> {
    let mut hosts_list = Vec::new();

    let file = File::open(filename).unwrap();
    let file = BufReader::new(file);

    for line in file.lines() {
        let line_str = line.unwrap().trim().to_owned();
        if line_str.is_empty() { continue; }
        if line_str.starts_with('#') { continue; }
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
        .arg(Arg::with_name("file")
            .short("f")
            .long("file")
            .takes_value(true)
            .required(true)
            .help("file with hosts: one per line"))
        .arg(Arg::with_name("user")
            .short("u")
            .long("user")
            .takes_value(true)
            .help("force SSH login as this username, instead of current user)"))
        .arg(Arg::with_name("parallel")
            .short("p")
            .long("parallel")
            .takes_value(true)
            .default_value("100")
            .help("number of parallel SSH sessions"))
        .arg(Arg::with_name("delay")
            .short("d")
            .long("delay")
            .takes_value(true)
            .default_value("10")
            .help("delay between each SSH session in milliseconds (ms)"))
        .arg(Arg::with_name("command")
            .takes_value(true)
            .required(true)
        )
        .get_matches();

    matches
}

fn assert_enough_fds(required_fds: usize) {
    let rlim_nofiles;

    unsafe {
        let mut rl = MaybeUninit::<libc::rlimit>::uninit();
        getrlimit(libc::RLIMIT_NOFILE, rl.as_mut_ptr());
        rlim_nofiles = rl.assume_init().rlim_cur as usize;
    };
    if rlim_nofiles <= required_fds {
        eprintln!("FATAL: Requested parallelism of {} is higher than RELIMIT_NOFILES of {}.", required_fds, rlim_nofiles);
        std::process::exit(1);
    }
}

fn main() {
    let matches = process_args();

    let hosts_list_file = matches.value_of("file").unwrap();
    let parallel_sessions = matches.value_of("parallel").unwrap().parse::<usize>().unwrap();
    let delay = matches.value_of("delay").unwrap().parse::<u64>().unwrap();
    let remote_command = matches.value_of("command").unwrap().to_owned();
    let mut remote_user = matches.value_of("user").unwrap().to_owned();

    if remote_user.is_empty() {
        remote_user = match users::get_current_username() {
            Some(username) => username.into_string().unwrap(),
            None => panic!("The current user does not exist!"),
        };
    }

    let hosts_list = get_hosts_list(hosts_list_file);
    let hosts_total = hosts_list.len();
    let n_workers = std::cmp::min(parallel_sessions, hosts_total);

    assert_enough_fds(n_workers);

    let pool = ThreadPool::new(n_workers);

    eprintln!("Mass parallel SSH in Rust (v{}), (c) {}", VERSION, AUTHOR);
    eprintln!(" * {} hosts from the list", hosts_list.len());
    eprintln!(" * {} threads", n_workers);
    eprintln!(" * {} ms delay", delay);
    eprintln!(" * command: {}\n", remote_command);

    let host_max_width: usize = hosts_list.iter().max_by(|x, y| x.len().cmp(&y.len())).unwrap().len();

    let hosts_left_lock = Arc::new(RwLock::new(hosts_total));
    let start_time = std::time::SystemTime::now();

    for host in hosts_list {
        let command_clone = remote_command.clone();
        let work_left_lock_clone = hosts_left_lock.clone();
        let user_clone = remote_user.clone();

        pool.execute(move || {
            let mut thread_name = "mps: ".to_owned();
            thread_name.push_str(&host);
            set_name(&thread_name).unwrap();

            let (out, exit_status) = execute(&host, &command_clone, &user_clone);
            let (hosts_left_pct, eta_str) = calculate_progress(hosts_total, work_left_lock_clone, start_time);
            print_output(&host, out, exit_status, host_max_width, hosts_left_pct, eta_str);
            thread_name = "mps: idle".to_owned();
            set_name(&thread_name).unwrap();
        });

        thread::sleep(time::Duration::from_millis(delay));
    }

    pool.join();
}
