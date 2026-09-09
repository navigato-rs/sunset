use std::{path, time};
use sunset_client::{Kind, StrictHostKeyChecking, config};

fn parse(text: &str) -> config::Config {
    config::Config::parse(text, path::Path::new("/tmp/sunset-test")).unwrap()
}

#[test]
fn each_hop_uses_its_own_identity_and_expands_overrides() {
    let config = parse(
        "Host dest\nHostName target.internal\nUser target\nProxyJump jumpuser@bastion:2022,second\nIdentityFile ~/.ssh/target\nHost bastion\nHostName gateway.example\nUser ignored\nPort 22\nIdentityFile ~/.ssh/%r_%p\nHostKeyAlias gw\nUserKnownHostsFile ~/.ssh/gateway_hosts\nIdentitiesOnly yes\nHost second\nUser relay\nIdentityFile ~/.ssh/relay\nHost *\nUser local\n",
    );
    let options =
        config.connection("dest", "fallback", time::Duration::from_secs(5)).unwrap();
    assert_eq!(options.host, "target.internal");
    assert_eq!(options.user, "target");
    assert_eq!(options.jumps.len(), 2);
    let first = &options.jumps[0];
    assert_eq!(first.host, "gateway.example");
    assert_eq!(first.user, "jumpuser");
    assert_eq!(first.port, 2022);
    assert_eq!(
        first.authentication.files,
        [path::PathBuf::from("/tmp/sunset-test/.ssh/jumpuser_2022")]
    );
    assert!(first.authentication.agent && first.authentication.identities_only);
    assert_eq!(
        first.known_hosts,
        path::PathBuf::from("/tmp/sunset-test/.ssh/gateway_hosts")
    );
    assert_eq!(first.host_key_alias.as_deref(), Some("gw"));
    assert_eq!(options.strict_host_key_checking, StrictHostKeyChecking::Yes);
    assert_eq!(options.jumps[1].user, "relay");
    assert!(options.jumps.iter().all(|hop| hop.jumps.is_empty()));
}

#[test]
fn connection_carries_stricthostkeychecking_per_hop() {
    let config = parse(
        "Host dest\nHostName dest.example\nUser dest\nStrictHostKeyChecking accept-new\nProxyJump bastion\nHost bastion\nHostName gw.example\nUser jump\nStrictHostKeyChecking no\n",
    );
    let options =
        config.connection("dest", "local", time::Duration::from_secs(5)).unwrap();
    assert_eq!(options.strict_host_key_checking, StrictHostKeyChecking::AcceptNew);
    assert_eq!(options.jumps[0].strict_host_key_checking, StrictHostKeyChecking::No);
}

#[test]
fn first_proxy_directive_wins_even_when_disabled() {
    let disabled = parse("Host *\nProxyJump none\nProxyCommand must-not-run\n");
    assert!(disabled.resolve("a").unwrap().unsupported.is_empty());
    assert!(disabled.resolve("a").unwrap().jumps.is_empty());
    let command = parse("Host *\nProxyCommand must-not-run\nProxyJump relay\n");
    assert_eq!(command.resolve("a").unwrap().unsupported, ["proxycommand"]);
    assert!(command.resolve("a").unwrap().jumps.is_empty());
    let jump = parse("Host dest\nProxyJump relay\nProxyCommand must-not-run\n");
    assert_eq!(jump.resolve("dest").unwrap().jumps.len(), 1);
    assert!(jump.resolve("dest").unwrap().unsupported.is_empty());
}

#[test]
fn hop_policy_and_nested_routes_fail_before_connecting() {
    for body in ["ProxyCommand forbidden", "ProxyJump other", "IdentityAgent custom"]
    {
        let config =
            parse(&format!("Host dest\nProxyJump relay\nHost relay\n{body}\n"));
        assert!(
            config.connection("dest", "test", time::Duration::from_secs(1)).is_err()
        );
    }
}

#[test]
fn jump_grammar_is_bounded_and_unambiguous() {
    let hops = config::parse_jumps("user@[::1]:2022,relay").unwrap();
    assert_eq!(hops[0].alias, "::1");
    assert_eq!(hops[0].port, Some(2022));
    for bad in [
        "",
        "a,",
        ",a",
        "a,,b",
        "a,b,c,d,e",
        "@a",
        "a@@b",
        "a:0",
        "a:65536",
        "a:-1",
        "[::1",
        "[::1]x",
        "::1",
        "ssh://host",
        "a\nb",
        "a b",
        "a;cmd",
    ] {
        assert!(config::parse_jumps(bad).is_err(), "{bad:?}");
    }
}

#[test]
fn invalid_routes_are_rejected_before_loading_trust_or_resolving_dns() {
    let config = parse("Host *\nUser test\n");
    let mut options = config
        .connection("nonexistent.invalid", "test", time::Duration::from_secs(1))
        .unwrap();
    options.jumps = vec![options.clone(); 5];
    let error = sunset_client::Connection::connect(&options).err().unwrap();
    assert_eq!(error.kind, Kind::Configuration);
    assert!(error.detail().contains("ProxyJump"));
}

#[test]
fn parsing_does_not_silently_drop_includes_or_invalid_booleans() {
    assert!(config::Config::parse("Include foo", path::Path::new("/tmp")).is_err());
    assert!(parse("Host a\nIdentitiesOnly maybe").resolve("a").is_err());
    assert!(
        parse("Host a\nUser test")
            .connection("a", "fallback", time::Duration::from_secs(1))
            .is_ok()
    );
}
