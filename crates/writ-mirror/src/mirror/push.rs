//! The upstream push: the updates a push decision accepted, sent upstream from the push's
//! quarantine before git moves the mirror's refs, all or none, each only if upstream still
//! has what the agent's push started from.

use super::{MAX_FETCH_OUTPUT, MirrorGuard, UpstreamUpdate};
use crate::quarantine::Quarantine;
use crate::{MirrorError, Result};

impl MirrorGuard {
    /// Pushes the accepted updates upstream from the push's quarantine, before git moves the
    /// mirror's refs: all or none (`--atomic`), each only if upstream still has what the
    /// agent's push started from (`--force-with-lease=<ref>:<old>`, empty for a new ref), so a
    /// ref upstream moved meanwhile is refused with the remote's reason. Within the sync's
    /// deadline, its bytes capped like a sync's.
    pub async fn push_upstream(
        &mut self,
        quarantine: &Quarantine,
        updates: &[UpstreamUpdate],
    ) -> Result<()> {
        let access = self.reach_upstream().await?;
        let mut args: Vec<String> = [
            "push",
            "--atomic",
            "--porcelain",
            "--no-verify",
            "--no-follow-tags",
            "--no-recurse-submodules",
        ]
        .iter()
        .map(|a| (*a).to_owned())
        .collect();
        for update in updates {
            let old = update.old.as_deref().unwrap_or_default();
            args.push(format!("--force-with-lease={}:{old}", update.name));
        }
        args.push("--".to_owned());
        args.push(self.repo.reach.url().to_owned());
        for update in updates {
            args.push(match &update.new {
                Some(new) => format!("{new}:{}", update.name),
                None => format!(":{}", update.name),
            });
        }
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        let pushed = self
            .run_upstream(
                &access,
                &args,
                Some(quarantine),
                self.shared.config.timeout,
                MAX_FETCH_OUTPUT,
            )
            .await;
        let finished = pushed?;
        if finished.status.success() {
            return Ok(());
        }
        let classified = self.classify(&access, &finished.stderr, "upstream push");
        let error = match classified {
            // What upstream said: the refused refs (porcelain), then its own words.
            MirrorError::Git { repo, .. } => MirrorError::Rejected {
                repo,
                reason: self.clean(
                    &access,
                    &super::notes::refused_lines(&finished.stdout, &finished.stderr),
                ),
                refs: self.clean(
                    &access,
                    &super::notes::refused_for_agent(&finished.stdout, &finished.stderr),
                ),
            },
            other => other,
        };
        // The operation ends here: its sockets, and the token it unwrapped, go.
        drop(access);
        Err(error)
    }
}
