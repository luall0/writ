//! Scenario 30, shell completion (M7.9.9): on the approver's machine, `writ completions` for
//! fish, zsh and bash, each registration sourced by its shell and a TAB in each: a command, a
//! flag, then the leases running on the stack's daemon for `writ revoke` (this scenario's
//! agent's among them, described by the daemon's facts, never its title) and the templates
//! of the policy in force for `writ admin template show`; with the daemon unreachable, the
//! same TAB offering no value and saying nothing.

use writ_e2e::Stack;
use writ_e2e::agent::{expect, ticket};

/// Drives bash's completion function as bash does on a TAB: `$2` the line.
const BASH: &str = r#"source "$1"
line=$2
read -ra COMP_WORDS <<< "$line"
[[ "$line" == *" " ]] && COMP_WORDS+=("")
COMP_CWORD=$(( ${#COMP_WORDS[@]} - 1 ))
COMP_LINE="$line"; COMP_POINT=${#line}; COMP_TYPE=9
_clap_complete_writ writ "${COMP_WORDS[COMP_CWORD]}" "${COMP_WORDS[COMP_CWORD-1]}"
for reply in "${COMPREPLY[@]}"; do printf '%s\n' "$reply"; done
"#;

/// Drives zsh's: compsys stood in for (`_describe` prints what it would offer), the
/// registration `$1`, the line `$2`.
const ZSH: &str = r#"compdef() { :; }
_describe() { print -rl -- "${(@P)3}"; }
words=(${(z)2}); [[ $2 == *" " ]] && words+=("")
CURRENT=${#words}
source $1
_clap_dynamic_completer_writ
"#;

/// What `shell` offers for `line` on the approver's machine, values only, sorted; nothing
/// may be said on stderr.
fn offered(stack: &Stack, shell: &str, line: &str) -> Vec<String> {
    let script = match shell {
        "fish" => {
            format!("fish --no-config -c 'source completion/writ.fish; complete -C \"{line}\"'")
        }
        "bash" => format!("bash completion/drive.bash completion/writ.bash '{line}'"),
        _ => format!("zsh -f completion/drive.zsh completion/_writ '{line}'"),
    };
    let (out, err) = expect(&stack.approver.run(&script), 0, &format!("{shell}: {line}"));
    assert_eq!(err, "", "{shell}: {line}");
    let mut values: Vec<String> = out
        .lines()
        .filter(|l| !l.is_empty())
        .map(|l| {
            let cut = match shell {
                "fish" => l.split('\t').next(),
                "zsh" => l.split(':').next(),
                _ => Some(l),
            };
            cut.unwrap_or_default().to_owned()
        })
        // Flags only when the word completed is one (with an empty word clap offers them too).
        .filter(|v| {
            !v.starts_with('-') || line.rsplit(' ').next().is_some_and(|w| w.starts_with('-'))
        })
        .collect();
    values.sort();
    values
}

#[test]
#[ignore = "end to end: make e2e"]
fn each_shell_completes_commands_flags_and_the_daemon_s_values_from_writ_completions() {
    let stack = Stack::shared();
    let agent = stack.agent("completion");
    let lease = agent.lease(&stack, &ticket(&["setup"], &["agent/completion"], "1h", ""));

    // Each shell's registration, as `make install` writes it; the drivers beside them.
    stack.approver.ok("mkdir -p completion");
    for (shell, file) in [
        ("fish", "writ.fish"),
        ("bash", "writ.bash"),
        ("zsh", "_writ"),
    ] {
        let (out, err) = expect(
            &stack.approver.run(&format!("writ completions {shell}")),
            0,
            &format!("writ completions {shell}"),
        );
        assert_eq!(err, "");
        assert!(out.contains("WRIT_COMPLETE"), "{shell}: {out}");
        assert!(out.contains("/usr/local/bin/writ"), "{shell}: {out}");
        stack
            .approver
            .write(&format!("completion/{file}"), &out, "0644");
    }
    stack.approver.write("completion/drive.bash", BASH, "0644");
    stack.approver.write("completion/drive.zsh", ZSH, "0644");

    for shell in ["fish", "bash", "zsh"] {
        assert_eq!(offered(&stack, shell, "writ rev"), ["revoke"], "{shell}");
        assert_eq!(
            offered(&stack, shell, "writ revoke --appr"),
            ["--approval-url"],
            "{shell}"
        );
        // The stack's running leases: this agent's among them (other scenarios hold theirs).
        let leases = offered(&stack, shell, "writ revoke ");
        assert!(
            leases.contains(&lease),
            "{shell}: {lease} not in {leases:?}"
        );
        assert!(
            leases.iter().all(|l| l.starts_with("wrt_")),
            "{shell}: {leases:?}"
        );
        assert!(
            offered(&stack, shell, "writ admin template show ").contains(&"feature".to_owned()),
            "{shell}"
        );
    }
    // fish shows each value's description: the daemon's facts, never the ticket's title.
    let (out, _) = expect(
        &stack
            .approver
            .run("fish --no-config -c 'source completion/writ.fish; complete -C \"writ revoke \"'"),
        0,
        "fish: writ revoke",
    );
    let line = out
        .lines()
        .find(|l| l.starts_with(&lease))
        .unwrap_or_else(|| panic!("{lease} not in {out}"));
    assert_eq!(line, format!("{lease}\tactive · feature · 1 repo"));

    // The daemon unreachable: no value, nothing said; the commands still complete.
    let nowhere = "WRIT_APPROVAL_URL=ssh://127.0.0.1:1";
    let (out, err) = expect(
        &stack.approver.run(&format!(
            "{nowhere} fish --no-config -c 'source completion/writ.fish; complete -C \"writ revoke \"'"
        )),
        0,
        "fish, unreachable",
    );
    assert_eq!(err, "");
    assert!(!out.contains("wrt_"), "{out}");
    let (out, _) = expect(
        &stack.approver.run(&format!(
            "{nowhere} fish --no-config -c 'source completion/writ.fish; complete -C \"writ rev\"'"
        )),
        0,
        "fish, unreachable, a command",
    );
    assert!(out.starts_with("revoke\t"), "{out}");

    // The lease ended: nothing of this scenario left running.
    stack.approver.ok(&format!("writ revoke {lease}"));
}
