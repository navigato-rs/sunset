//! Run only against the disposable servers created by sshd.sh.
use std::{
    env, fs,
    io::{self, Read, Write},
    path, thread, time,
};
use sunset_client::{Authentication, Channel, Connection, Kind, Options};

fn fixture() -> (path::PathBuf, Vec<u16>) {
    let root =
        env::var_os("SUNSET_TEST_ROOT").expect("run client/tests/sshd.sh").into();
    let ports = env::var("SUNSET_TEST_PORTS")
        .unwrap()
        .split(',')
        .map(|port| port.parse().unwrap())
        .collect();
    (root, ports)
}

fn options(hops: usize) -> Options {
    let (root, ports) = fixture();
    let endpoint = |i| Options {
        host: "127.0.0.1".into(),
        port: ports[i],
        user: env::var("SUNSET_TEST_USER").unwrap(),
        known_hosts: root.join("known_hosts"),
        host_key_alias: None,
        authentication: Authentication::identity(root.join(format!("identity{i}"))),
        timeout: time::Duration::from_secs(10),
        jumps: Vec::new(),
    };
    let mut target = endpoint(2);
    target.jumps = (0..hops).map(endpoint).collect();
    target
}

fn collect(mut channel: Channel, expected: &[u8]) {
    let deadline = time::Instant::now() + time::Duration::from_secs(20);
    let mut out = Vec::new();
    let mut err = Vec::new();
    let mut bytes = [0; 16384];
    while !channel.eof() {
        match channel.read(&mut bytes) {
            Ok(n) => out.extend_from_slice(&bytes[..n]),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => (),
            Err(e) => panic!("read: {e}"),
        }
        match channel.read_stderr(&mut bytes) {
            Ok(n) => err.extend_from_slice(&bytes[..n]),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => (),
            Err(e) => panic!("stderr: {e}"),
        }
        assert!(out.len() <= expected.len(), "unexpected extra output");
        channel.wait(deadline).unwrap_or_else(|e| {
            panic!("wait after {}/{} bytes: {e}", out.len(), expected.len())
        });
    }
    assert_eq!(out, expected);
    assert!(err.is_empty(), "stderr: {}", String::from_utf8_lossy(&err));
}

#[test]
#[ignore = "disposable sshd fixture"]
fn direct_and_two_bastions_use_distinct_identities() {
    for hops in 0..=2 {
        let channel = Connection::connect(&options(hops))
            .unwrap()
            .exec("printf route-ok")
            .unwrap();
        collect(channel, b"route-ok");
    }
}

#[test]
#[ignore = "disposable sshd fixture"]
fn routed_streams_exceed_queue_budget_without_loss() {
    let expected = vec![b'x'; 2 * 1024 * 1024];
    for hops in 0..=2 {
        let channel = Connection::connect(&options(hops))
            .unwrap()
            .exec(
                "python3 -c 'import sys; sys.stdout.buffer.write(b\"x\" * 2097152)'",
            )
            .unwrap();
        collect(channel, &expected);
    }
}

#[test]
#[ignore = "disposable sshd fixture"]
fn routed_writes_and_binary_reads_round_trip() {
    let expected: Vec<u8> = (0..131072).map(|n| (n % 251) as u8).collect();
    let command = "python3 -c 'import sys; b=sys.stdin.buffer.read(131072); sys.stdout.buffer.write(b)'";
    let mut channel =
        Connection::connect(&options(2)).unwrap().exec(command).unwrap();
    let deadline = time::Instant::now() + time::Duration::from_secs(20);
    let mut sent = 0;
    while sent < expected.len() {
        match channel.write(&expected[sent..]) {
            Ok(n) => sent += n,
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                channel.wait(deadline).unwrap()
            }
            Err(e) => panic!("write: {e}"),
        }
    }
    loop {
        match channel.flush() {
            Ok(()) => break,
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                channel.wait(deadline).unwrap()
            }
            Err(e) => panic!("flush: {e}"),
        }
    }
    collect(channel, &expected);
}

#[test]
#[ignore = "disposable sshd fixture"]
fn every_hop_checks_trust_before_authentication() {
    let (root, _) = fixture();
    for position in 0..3 {
        for (name, kind) in [
            ("unknown_hosts", Kind::UnknownHostKey),
            ("wrong_hosts", Kind::ChangedHostKey),
        ] {
            let mut opts = options(2);
            let endpoint =
                if position == 2 { &mut opts } else { &mut opts.jumps[position] };
            endpoint.known_hosts = root.join(name);
            // If trust is bypassed, authentication has no usable identity.
            endpoint.authentication = Authentication::identity(root.join("missing"));
            let error = Connection::connect(&opts).err().unwrap();
            assert_eq!(error.kind, kind, "hop {position}: {error}");
        }
    }
}

#[test]
#[ignore = "disposable sshd fixture"]
fn refused_bastion_never_falls_back_to_reachable_target() {
    let (root, ports) = fixture();
    let mut opts = options(1);
    opts.jumps[0].port = ports[3];
    opts.jumps[0].authentication = Authentication::identity(root.join("identity3"));
    assert!(Connection::connect(&opts).is_err());
    collect(
        Connection::connect(&options(0)).unwrap().exec("printf reachable").unwrap(),
        b"reachable",
    );
}

#[test]
#[ignore = "disposable sshd fixture"]
fn restricted_agent_can_sign_a_configured_public_identity() {
    let (root, _) = fixture();
    let mut opts = options(1);
    opts.authentication = Authentication {
        files: vec![root.join("identity2.pub")],
        agent: true,
        identities_only: true,
    };
    collect(
        Connection::connect(&opts).unwrap().exec("printf agent-ok").unwrap(),
        b"agent-ok",
    );
    opts.authentication.files = vec![root.join("identity0.pub")];
    let error = Connection::connect(&opts).err().unwrap();
    assert_eq!(error.kind, Kind::Authentication, "{error}");
}

#[test]
#[ignore = "disposable sshd fixture"]
fn routed_idle_wait_is_wakeable_and_deadline_bounded() {
    let mut channel =
        Connection::connect(&options(2)).unwrap().exec("sleep 3").unwrap();
    let wake = channel.waker();
    let sender = thread::spawn(move || {
        thread::sleep(time::Duration::from_millis(100));
        wake.notify();
    });
    let deadline = time::Instant::now() + time::Duration::from_secs(1);
    while !channel.take_wakeup() {
        channel.wait(deadline).unwrap();
    }
    sender.join().unwrap();
    let deadline = time::Instant::now() + time::Duration::from_millis(100);
    loop {
        if let Err(error) = channel.wait(deadline) {
            assert_eq!(error.kind, Kind::Timeout);
            break;
        }
    }
    channel.abort();
}

#[test]
#[ignore = "disposable sshd fixture"]
fn configuration_builds_a_working_route() {
    let (root, ports) = fixture();
    let user = env::var("SUNSET_TEST_USER").unwrap();
    let mut text = String::new();
    for (i, port) in ports.iter().enumerate().take(3) {
        text.push_str(&format!("Host host{i}\nHostName 127.0.0.1\nPort {}\nUser {user}\nIdentityFile {}\nUserKnownHostsFile {}\nIdentitiesOnly yes\n", port, root.join(format!("identity{i}")).display(), root.join("known_hosts").display()));
        if i == 2 {
            text.push_str("ProxyJump host0,host1\n");
        }
    }
    fs::create_dir_all(root.join("home/.ssh")).unwrap();
    fs::write(root.join("home/.ssh/config"), text).unwrap();
    let config = sunset_client::config::Config::load(&root.join("home")).unwrap();
    let opts =
        config.connection("host2", &user, time::Duration::from_secs(10)).unwrap();
    collect(
        Connection::connect(&opts).unwrap().exec("printf config-ok").unwrap(),
        b"config-ok",
    );
}

#[test]
#[ignore = "disposable sshd fixture"]
fn eof_closes_only_stdin_and_retains_nonzero_exit() {
    for hops in 0..=2 {
        let mut channel = Connection::connect(&options(hops))
            .unwrap()
            .exec("cat; printf diagnostic >&2; exit 7")
            .unwrap();
        let deadline = time::Instant::now() + time::Duration::from_secs(10);
        let input = vec![b'x'; 131072];
        let mut written = 0;
        let mut out = Vec::new();
        let mut err = Vec::new();
        let mut eof_sent = false;
        let mut buf = [0; 8192];
        while !channel.finished() {
            if written < input.len() {
                match channel.write(&input[written..]) {
                    Ok(n) => written += n,
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => (),
                    Err(e) => panic!("write: {e}"),
                }
            } else if !eof_sent {
                match channel.finish_input() {
                    Ok(()) => eof_sent = true,
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => (),
                    Err(e) => panic!("EOF: {e}"),
                }
            }
            match channel.read(&mut buf) {
                Ok(n) => out.extend_from_slice(&buf[..n]),
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => (),
                Err(e) => panic!("read: {e}"),
            }
            match channel.read_stderr(&mut buf) {
                Ok(n) => err.extend_from_slice(&buf[..n]),
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => (),
                Err(e) => panic!("stderr: {e}"),
            }
            channel.wait(deadline).unwrap();
        }
        assert!(eof_sent);
        assert_eq!(out, input);
        assert_eq!(err, b"diagnostic");
        assert_eq!(channel.exit_status(), Some(&sunset_client::ExitStatus::Code(7)));
        assert_eq!(
            channel.write(b"late").unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
        channel.finish_input().unwrap();
    }
}
