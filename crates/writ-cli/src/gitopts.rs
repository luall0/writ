//! git's global options, read as git reads them (`git.c`'s `handle_options`), so `writ git`
//! finds the repository a command works in: in order, up to the first argument that isn't
//! one (the command). `-C <dir>` moves into `<dir>` (relative to the one before; an empty
//! one is no move), `--git-dir`, `--work-tree` and `--bare` name the repository and its
//! working tree, the others change nothing about which repository it is. git itself then
//! resolves the repository from the options that do (`git <them> rev-parse
//! --git-common-dir`, `GIT_DIR` and the rest of the environment as the command will see
//! them), so nothing is guessed.
//!
//! An option git doesn't take before a command, or one missing its value, is refused with its
//! reason: never skipped, so what `writ git` resolves is what git would work in. The options
//! that print something and exit (`--version`, `--help`, `--exec-path` alone…) work in no
//! repository.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

/// What git's arguments before the command say.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Parsed {
    /// A command (or none: git prints its usage).
    Command {
        /// The directory git works from once every `-C` is applied.
        dir: PathBuf,
        /// The options that say which repository it is, as given and in order (`-C`,
        /// `--git-dir`, `--work-tree`, `--bare`): what `git rev-parse` is run with.
        locate: Vec<OsString>,
        /// The command git runs (`fetch`, `commit`…), when there is one and it is UTF-8.
        command: Option<String>,
    },
    /// An option that prints and exits (`--version`, `--help`, `--exec-path`,
    /// `--html-path`…): no repository involved.
    Informational,
}

/// Options that take their value as the next argument (and, for those listed in
/// [`JOINED`], also after `=`).
const SEPARATE: &[&str] = &[
    "-C",
    "-c",
    "--git-dir",
    "--work-tree",
    "--namespace",
    "--super-prefix",
    "--attr-source",
    "--config-env",
    "--shallow-file",
];

/// Options that take their value after `=`.
const JOINED: &[&str] = &[
    "--git-dir",
    "--work-tree",
    "--namespace",
    "--super-prefix",
    "--attr-source",
    "--config-env",
    "--exec-path",
];

/// Options without a value.
const FLAGS: &[&str] = &[
    "-p",
    "--paginate",
    "-P",
    "--no-pager",
    "--bare",
    "--no-replace-objects",
    "--no-lazy-fetch",
    "--no-optional-locks",
    "--no-advice",
    "--literal-pathspecs",
    "--glob-pathspecs",
    "--noglob-pathspecs",
    "--icase-pathspecs",
];

/// Options that print and exit (or turn into `git help`).
const INFORMATIONAL: &[&str] = &[
    "--exec-path",
    "--html-path",
    "--man-path",
    "--info-path",
    "-h",
    "--help",
    "-v",
    "--version",
];

/// The options that say which repository a command works in: kept for `git rev-parse`.
const LOCATING: &[&str] = &["-C", "--git-dir", "--work-tree", "--bare"];

/// Reads git's global options in `args`, from the directory `cwd`.
pub fn parse(cwd: &Path, args: &[OsString]) -> Result<Parsed, String> {
    let mut dir = cwd.to_path_buf();
    let mut locate = Vec::new();
    let mut rest = args;
    while let [arg, more @ ..] = rest {
        if !arg.as_encoded_bytes().starts_with(b"-") {
            break;
        }
        let Some(option) = arg.to_str() else {
            return Err(format!(
                "{}: not an option git takes before its command",
                crate::display::clean(&arg.to_string_lossy())
            ));
        };
        if INFORMATIONAL.contains(&option) || option.starts_with("--list-cmds=") {
            return Ok(Parsed::Informational);
        }
        if FLAGS.contains(&option) {
            if LOCATING.contains(&option) {
                locate.push(arg.clone());
            }
            rest = more;
            continue;
        }
        if let Some((name, _)) = option.split_once('=')
            && JOINED.contains(&name)
        {
            if LOCATING.contains(&name) {
                locate.push(arg.clone());
            }
            rest = more;
            continue;
        }
        if SEPARATE.contains(&option) {
            let [value, after @ ..] = more else {
                return Err(format!("{option} needs a value, as git asks"));
            };
            if option == "-C" && !value.is_empty() {
                dir = dir.join(value);
            }
            if LOCATING.contains(&option) {
                locate.push(arg.clone());
                locate.push(value.clone());
            }
            rest = after;
            continue;
        }
        return Err(format!(
            "{}: not an option git takes before its command (writ git refuses what it can't \
             place: put the command's own options after the command)",
            crate::display::clean(option)
        ));
    }
    Ok(Parsed::Command {
        dir,
        locate,
        command: rest.first().and_then(|c| c.to_str()).map(str::to_owned),
    })
}

/// The repository's shared git directory, as git resolves it with `locate` (the options
/// [`parse`] kept) from this process's directory and environment; git's reason when there is
/// none.
pub fn common_dir(locate: &[OsString]) -> Result<PathBuf, String> {
    // PATH: the agent host's own git, the one the command will run.
    let out = std::process::Command::new("git")
        .args(locate)
        .args(["rev-parse", "--path-format=absolute", "--git-common-dir"])
        .stdin(std::process::Stdio::null())
        .output()
        .map_err(|e| format!("cannot run git: {e}"))?;
    if !out.status.success() {
        let why = String::from_utf8_lossy(&out.stderr);
        return Err(crate::display::clean_lines(why.trim()));
    }
    let text = String::from_utf8(out.stdout)
        .map_err(|_| "git named a repository whose path isn't UTF-8".to_owned())?;
    Ok(PathBuf::from(text.trim_end_matches('\n')))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn os(args: &[&str]) -> Vec<OsString> {
        args.iter().map(OsString::from).collect()
    }

    fn command(cwd: &str, args: &[&str]) -> (PathBuf, Vec<String>) {
        match parse(Path::new(cwd), &os(args)).unwrap() {
            Parsed::Command { dir, locate, .. } => (
                dir,
                locate
                    .iter()
                    .map(|a| a.to_string_lossy().into_owned())
                    .collect(),
            ),
            Parsed::Informational => panic!("{args:?}: informational"),
        }
    }

    #[test]
    fn dash_c_moves_from_the_directory_before_in_order() {
        assert_eq!(command("/w", &["status"]).0, PathBuf::from("/w"));
        assert_eq!(
            command("/w", &["-C", "api", "log"]).0,
            PathBuf::from("/w/api")
        );
        assert_eq!(
            command("/w", &["-C", "api", "-C", "sub", "log"]).0,
            PathBuf::from("/w/api/sub")
        );
        assert_eq!(
            command("/w", &["-C", "api", "-C", "/abs", "log"]).0,
            PathBuf::from("/abs")
        );
        // An empty -C is no move, as in git.
        assert_eq!(command("/w", &["-C", "", "log"]).0, PathBuf::from("/w"));
        // Only before the command: a later -C is the command's (`log -C`).
        assert_eq!(command("/w", &["log", "-C", "/r"]).0, PathBuf::from("/w"));
    }

    #[test]
    fn every_global_option_is_read_and_only_the_locating_ones_kept() {
        let (dir, locate) = command(
            "/w",
            &[
                "-c",
                "user.name=x",
                "--config-env",
                "core.editor=EDITOR",
                "--config-env=a.b=C",
                "-p",
                "--paginate",
                "-P",
                "--no-pager",
                "--namespace",
                "ns",
                "--namespace=ns",
                "--attr-source",
                "HEAD",
                "--attr-source=HEAD",
                "--super-prefix",
                "p/",
                "--super-prefix=p/",
                "--shallow-file",
                "f",
                "--exec-path=/x",
                "--no-replace-objects",
                "--no-lazy-fetch",
                "--no-optional-locks",
                "--no-advice",
                "--literal-pathspecs",
                "--glob-pathspecs",
                "--noglob-pathspecs",
                "--icase-pathspecs",
                "-C",
                "api",
                "--git-dir",
                "g",
                "--git-dir=h",
                "--work-tree",
                "t",
                "--work-tree=u",
                "--bare",
                "commit",
                "-m",
                "x",
            ],
        );
        assert_eq!(dir, PathBuf::from("/w/api"));
        assert_eq!(
            locate,
            [
                "-C",
                "api",
                "--git-dir",
                "g",
                "--git-dir=h",
                "--work-tree",
                "t",
                "--work-tree=u",
                "--bare"
            ]
        );
        // A -c value that looks like an option is the option's value, not one of git's.
        let (dir, locate) = command("/w", &["-c", "-C", "status"]);
        assert_eq!(dir, PathBuf::from("/w"));
        assert!(locate.is_empty());
    }

    #[test]
    fn options_that_print_and_exit_need_no_repository() {
        for args in [
            &["--version"][..],
            &["-v"],
            &["--help", "commit"],
            &["-h"],
            &["--exec-path"],
            &["--html-path"],
            &["--man-path"],
            &["--info-path"],
            &["--list-cmds=main"],
            &["-C", "api", "--version"],
        ] {
            assert_eq!(
                parse(Path::new("/w"), &os(args)),
                Ok(Parsed::Informational),
                "{args:?}"
            );
        }
    }

    #[test]
    fn what_git_would_refuse_or_read_otherwise_is_refused_with_its_reason() {
        for option in [
            "-C",
            "-c",
            "--git-dir",
            "--work-tree",
            "--config-env",
            "--namespace",
        ] {
            assert_eq!(
                parse(Path::new("/w"), &os(&["-P", option])),
                Err(format!("{option} needs a value, as git asks")),
            );
        }
        // With its value, the same option is read.
        assert!(parse(Path::new("/w"), &os(&["-P", "--git-dir", "g"])).is_ok());
        // Joined forms git doesn't take, unknown options, a command's option in front.
        for option in [
            "-Capi",
            "-cuser.name=x",
            "--git-dirx",
            "--bogus",
            "-m",
            "--all",
            "--",
        ] {
            let error = parse(Path::new("/w"), &os(&[option, "status"])).unwrap_err();
            assert_eq!(
                error,
                format!(
                    "{option}: not an option git takes before its command (writ git refuses \
                     what it can't place: put the command's own options after the command)"
                )
            );
        }
        // Hostile text is shown escaped.
        let error = parse(Path::new("/w"), &os(&["--\u{1b}[2J", "status"])).unwrap_err();
        assert!(error.starts_with("--\\u{1b}[2J: not an option"), "{error}");
        // An option that isn't UTF-8.
        use std::os::unix::ffi::OsStringExt as _;
        let bytes = OsString::from_vec(b"--\xff".to_vec());
        let error = parse(Path::new("/w"), &[bytes, OsString::from("status")]).unwrap_err();
        assert!(
            error.ends_with(": not an option git takes before its command"),
            "{error}"
        );
    }
}
