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

## License

This project is licensed under the [Apache License 2.0](LICENSE).

For commercial licensing, extended support, or custom features, please contact me.
