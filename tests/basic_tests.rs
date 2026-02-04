#[path = "../src/ssh.rs"]
mod ssh;

use tracing_test::traced_test;

/// Test that high parallelism doesn't cause mlock panics.
///
/// Background: russh-cryptovec uses mlock() to protect sensitive cryptographic
/// data in memory. With russh 0.49.x (cryptovec 0.48.0), mlock failures cause
/// panics. With russh 0.57+ (cryptovec 0.52.0+), failures are handled gracefully.
///
/// This test spawns many concurrent SSH connections to trigger memory pressure.
/// With the old version, this would panic with "Failed to lock memory".
/// With the fixed version, connections should complete (success or error) without panic.
///
/// Note: This test requires localhost to have SSH enabled, otherwise it just tests
/// that connection failures don't panic (which is still useful).
#[tokio::test]
#[traced_test]
async fn test_high_parallelism_no_mlock_panic() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    let _ = tracing_log::LogTracer::init();

    // Try to lower RLIMIT_MEMLOCK to increase chances of triggering the issue
    // This may fail if we don't have permission, which is fine
    #[cfg(unix)]
    {
        use libc::{rlimit, setrlimit, RLIMIT_MEMLOCK};
        let limit = rlimit {
            rlim_cur: 64 * 1024,  // 64KB soft limit
            rlim_max: 64 * 1024,  // 64KB hard limit (may fail if lower than current)
        };
        unsafe {
            // Ignore errors - we may not have permission to lower the limit
            let _ = setrlimit(RLIMIT_MEMLOCK, &limit);
        }
    }

    let parallelism = 100;
    let completed = Arc::new(AtomicUsize::new(0));
    let panicked = Arc::new(AtomicUsize::new(0));

    let mut handles = vec![];

    for i in 0..parallelism {
        let completed = Arc::clone(&completed);
        let panicked = Arc::clone(&panicked);

        handles.push(tokio::spawn(async move {
            // Use catch_unwind to detect panics from the mlock issue
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                // We need to block on the async function inside catch_unwind
                // This is a bit awkward but necessary for panic catching
            }));

            // Actually run the SSH connection (outside catch_unwind since it's async)
            // The panic would occur in the russh internals, which tokio will catch
            let host = if i % 2 == 0 { "localhost" } else { "127.0.0.1" };
            let (_output, _exit_code) =
                ssh::execute(host, "echo test", "nobody", &ssh::SshBackend::Russh).await;

            completed.fetch_add(1, Ordering::SeqCst);
        }));
    }

    // Wait for all tasks, tracking any that panicked
    for handle in handles {
        match handle.await {
            Ok(_) => {}
            Err(e) => {
                if e.is_panic() {
                    panicked.fetch_add(1, Ordering::SeqCst);
                    let panic_msg = if let Some(s) = e.into_panic().downcast_ref::<&str>() {
                        s.to_string()
                    } else {
                        "unknown panic".to_string()
                    };
                    eprintln!("Task panicked: {}", panic_msg);
                }
            }
        }
    }

    let total_completed = completed.load(Ordering::SeqCst);
    let total_panicked = panicked.load(Ordering::SeqCst);

    eprintln!(
        "High parallelism test: {} completed, {} panicked out of {}",
        total_completed, total_panicked, parallelism
    );

    // The key assertion: no panics should occur due to mlock failures
    assert_eq!(
        total_panicked, 0,
        "Tasks panicked (likely due to mlock failure). \
         This indicates russh-cryptovec is panicking on memory lock failures. \
         Upgrade to russh 0.57+ which uses cryptovec 0.52.0+ with graceful handling."
    );

    // All tasks should complete (with success or error, doesn't matter)
    assert_eq!(
        total_completed, parallelism,
        "Not all tasks completed. {} of {} finished.",
        total_completed, parallelism
    );
}

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
