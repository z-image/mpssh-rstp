#[path = "../src/ssh.rs"]
mod ssh;

use tracing_test::traced_test;

#[tokio::test]
#[traced_test]
async fn test_command_execution_bad_host_retries() {
    log::info!("Starting test_command_execution_bad_host_retries");

    let _ = tracing_log::LogTracer::init(); // Needed for logs_contain()

    let backends = vec![ssh::SshBackend::Russh, ssh::SshBackend::LibSsh2];

    for backend in backends {
        let (output, exit_code) = ssh::execute("bad_host", "echo Hello", "user", &backend).await;
        eprintln!(
            "ssh::execute failed for backend {:?}. Exit code: {}, Output: {:?}",
            backend, exit_code, output
        );

        // Asser that we got an error message
        assert!(output.is_some());
        assert!(output
            .unwrap()
            .contains("Temporary failure in name resolution"));
        assert_eq!(exit_code, 1);

        let msg = format!(
            "Executing command 'echo Hello' on user@bad_host using {}",
            backend
        );
        assert!(logs_contain(&msg));

        // Check for failure in a more implementation-independent way
        assert!(logs_contain("connection to bad_host:22 failure"));
        assert!(logs_contain("Temporary failure in name resolution"));
    }
}
