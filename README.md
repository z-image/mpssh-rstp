Executes an SSH command simultaneously on many hosts.

It's really very fast (depending on your workstation, connection, servers).

```
❯ time  mpssh -f servers.txt -p 1700 -d2  true

 * using russh backend
 * 1626 hosts from the list
 * 1626 threads
 * 2 ms delay
 * command: true

real	0m8.081s
user	0m2.576s
sys	0m2.812s

~ took 8s
```

## Usage

```
mpssh-rstp [FLAGS] [OPTIONS] <command> --file <file> [SUBCOMMAND]

FLAGS:
        --debug              
    -h, --help               Prints help information
    -s, --suppress-output    Suppress output from the remote command (only show progress)
    -V, --version            Prints version information
    -w, --write-to-file      Write output to files, one per host

OPTIONS:
    -d, --delay <delay>                delay between each SSH session in milliseconds (ms) [default: 10]
    -f, --file <file>                  file with hosts: one per line
    -p, --parallel <parallel>          number of parallel SSH sessions [default: 100]
    -b, --ssh-backend <ssh_backend>    SSH backend to use (russh, libssh2) [default: russh]  [possible values: russh,
                                       libssh2]
    -u, --user <user>                  force SSH login as this username, instead of current user)

ARGS:
    <command>
```

## Per-host results

Each output line has the form `host -> text` or `host => text`. The `->` marker shows that the remote command exited with status 0. The `=>` marker shows a different status or a failure.

- With the default russh backend: if mpssh-rstp cannot run the command on a host, it prints one `=>` line. The line names the step that failed, for example `agent connect: Resource temporarily unavailable (os error 11)`.
- With the default russh backend: if the remote command stops without an exit status, or a signal stops it, mpssh-rstp keeps the output. It adds a last line with the reason, for example `exec: channel closed without exit status` or `exec: killed by signal TERM`. The status is 255, as with OpenSSH `ssh`.
- The exit status of mpssh-rstp does not show host failures yet. A host with no output and status 0 gets no line at all. To make sure that all hosts ran the command, make the command print a result line on every host, for example `cmd; rc=$?; echo "rc=$rc"; exit "$rc"`. The `->` and `=>` markers still show the exit status of the command. A host without an `rc=` line did not confirm that the command completed. If the output of the command does not end with a newline, the `rc=` text is added to its last line. Compare the hosts in the output with the host list, and read the `=>` lines.

## License

This project is licensed under the [Apache License 2.0](LICENSE).

For commercial licensing, extended support, or custom features, please contact me.
