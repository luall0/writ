//! `writ admin`'s dispatch: each subcommand handed to what runs it (the review after M7.6,
//! W-13: out of `main.rs`).

use crate::approver;
use crate::cli::{
    AdminCommand, AutoUnsealCommand, CaCommand, EntryCommand, HostCommand, KeyCommand, RepoCommand,
    TlsCommand,
};
use crate::{Exit, Paths, signer};

/// `writ admin <command>`.
pub(crate) async fn admin(paths: &Paths, command: &AdminCommand) -> anyhow::Result<Exit> {
    match command {
        AdminCommand::Show { target, url } => {
            approver::admin_show(paths, &url.get(paths)?, approver::admin_target(target)?).await
        }
        AdminCommand::Repo { command } => match command {
            RepoCommand::Entry(command) => {
                entry_command(paths, writ_core::config::Section::Repos, command, None).await
            }
            RepoCommand::Check { repo, url } => {
                approver::guided_check(paths, &url.get(paths)?, repo).await
            }
            RepoCommand::Status { repo, url } => {
                approver::repo_status(paths, &url.get(paths)?, repo.as_deref()).await
            }
        },
        AdminCommand::Host { command } => match command {
            HostCommand::Entry(command) => {
                entry_command(
                    paths,
                    writ_core::config::Section::UpstreamHosts,
                    command,
                    None,
                )
                .await
            }
            HostCommand::Rescan {
                host,
                proxy,
                yes,
                url,
                signer: args,
            } => {
                let signer = signer(paths, args);
                approver::guided_rescan(
                    paths,
                    &url.get(paths)?,
                    &signer,
                    host,
                    proxy.as_deref(),
                    *yes,
                )
                .await
            }
        },
        AdminCommand::Proxy { command } => {
            entry_command(paths, writ_core::config::Section::Proxies, command, None).await
        }
        AdminCommand::Recipient { command } => {
            entry_command(paths, writ_core::config::Section::Recipients, command, None).await
        }
        AdminCommand::Template { command } => {
            use writ_core::config::Section;
            let (command, from) = command.split();
            entry_command(paths, Section::Templates, &command, from.as_deref()).await
        }
        AdminCommand::Key { command } => {
            use writ_core::config::Section;
            match command {
                KeyCommand::List { url } => {
                    approver::manage_list(paths, &url.get(paths)?, Section::Keys).await
                }
                KeyCommand::Show { id, public, url } => {
                    approver::manage_show(paths, &url.get(paths)?, Section::Keys, id, *public).await
                }
                KeyCommand::Add {
                    name,
                    given,
                    yes,
                    url,
                    signer: args,
                } => {
                    let signer = signer(paths, args);
                    approver::guided_add(
                        paths,
                        &url.get(paths)?,
                        &signer,
                        Section::Keys,
                        name,
                        given,
                        None,
                        *yes,
                    )
                    .await
                }
                KeyCommand::Edit {
                    name,
                    yes,
                    url,
                    signer: args,
                } => {
                    let signer = signer(paths, args);
                    approver::guided_edit(
                        paths,
                        &url.get(paths)?,
                        &signer,
                        Section::Keys,
                        name,
                        *yes,
                    )
                    .await
                }
                KeyCommand::Set {
                    name,
                    edits,
                    yes,
                    url,
                    signer: args,
                } => {
                    let signer = signer(paths, args);
                    approver::manage_set(
                        paths,
                        &url.get(paths)?,
                        &signer,
                        Section::Keys,
                        name,
                        edits,
                        *yes,
                    )
                    .await
                }
                KeyCommand::Remove {
                    name,
                    yes,
                    url,
                    signer: args,
                } => {
                    let signer = signer(paths, args);
                    approver::manage_remove(
                        paths,
                        &url.get(paths)?,
                        &signer,
                        Section::Keys,
                        name,
                        *yes,
                    )
                    .await
                }
                KeyCommand::Rotate {
                    id,
                    name,
                    backend,
                    yes,
                    url,
                    signer: args,
                } => {
                    let signer = signer(paths, args);
                    approver::guided_rotate(
                        paths,
                        &url.get(paths)?,
                        &signer,
                        id,
                        name.as_deref(),
                        backend.as_deref(),
                        *yes,
                    )
                    .await
                }
            }
        }
        AdminCommand::Apply {
            target,
            file,
            yes,
            url,
            signer: args,
        } => {
            approver::admin_apply(
                paths,
                &url.get(paths)?,
                &signer(paths, args),
                approver::admin_target(target)?,
                file,
                *yes,
            )
            .await
        }
        AdminCommand::Token {
            id,
            yes,
            url,
            signer: args,
        } => {
            let id: writ_core::names::KeyId = id
                .parse()
                .map_err(|e| anyhow::anyhow!("token id {id:?}: {e}"))?;
            approver::admin_token(paths, &url.get(paths)?, &signer(paths, args), &id, *yes).await
        }
        AdminCommand::Tls {
            command:
                TlsCommand::Rotate {
                    backend,
                    yes,
                    url,
                    signer: args,
                },
        } => {
            approver::admin_tls_rotate(
                paths,
                &url.get(paths)?,
                &signer(paths, args),
                backend.as_deref(),
                *yes,
            )
            .await
        }
        AdminCommand::Ca {
            command: CaCommand::Show { url },
        } => approver::admin_ca_show(paths, &url.get(paths)?).await,
        AdminCommand::Ca {
            command:
                CaCommand::Rotate {
                    backend,
                    yes,
                    url,
                    signer: args,
                },
        } => {
            approver::admin_ca_rotate(
                paths,
                &url.get(paths)?,
                &signer(paths, args),
                backend.as_deref(),
                *yes,
            )
            .await
        }
        AdminCommand::AutoUnseal {
            command: AutoUnsealCommand::Status { url },
        } => approver::auto_unseal_status(paths, &url.get(paths)?).await,
        AdminCommand::AutoUnseal {
            command:
                AutoUnsealCommand::On {
                    yes,
                    url,
                    signer: args,
                },
        } => {
            approver::auto_unseal_set(paths, &url.get(paths)?, &signer(paths, args), true, *yes)
                .await
        }
        AdminCommand::AutoUnseal {
            command:
                AutoUnsealCommand::Off {
                    yes,
                    url,
                    signer: args,
                },
        } => {
            approver::auto_unseal_set(paths, &url.get(paths)?, &signer(paths, args), false, *yes)
                .await
        }
    }
}

/// `writ admin repo|template|host <verb>`, for `section` (`from`: a template's `add --from`).
pub(crate) async fn entry_command(
    paths: &Paths,
    section: writ_core::config::Section,
    command: &EntryCommand,
    from: Option<&str>,
) -> anyhow::Result<Exit> {
    match command {
        EntryCommand::List { url } => approver::manage_list(paths, &url.get(paths)?, section).await,
        EntryCommand::Show { name, url } => {
            approver::manage_show(paths, &url.get(paths)?, section, name, false).await
        }
        EntryCommand::Add {
            name,
            given,
            yes,
            url,
            signer: args,
        } => {
            let signer = signer(paths, args);
            approver::guided_add(
                paths,
                &url.get(paths)?,
                &signer,
                section,
                name,
                given,
                from,
                *yes,
            )
            .await
        }
        EntryCommand::Edit {
            name,
            yes,
            url,
            signer: args,
        } => {
            let signer = signer(paths, args);
            approver::guided_edit(paths, &url.get(paths)?, &signer, section, name, *yes).await
        }
        EntryCommand::Set {
            name,
            edits,
            yes,
            url,
            signer: args,
        } => {
            let signer = signer(paths, args);
            approver::manage_set(paths, &url.get(paths)?, &signer, section, name, edits, *yes).await
        }
        EntryCommand::Remove {
            name,
            yes,
            url,
            signer: args,
        } => {
            let signer = signer(paths, args);
            approver::manage_remove(paths, &url.get(paths)?, &signer, section, name, *yes).await
        }
    }
}
