//! The approver's watch (M7.8): the tickets waiting for a signature, as soon as they change.
//! What the approval popup's `writ sign --ui` holds open, so a ticket shows the moment it is
//! submitted, and its window closes the moment it stops waiting.

use std::sync::Arc;
use std::time::Duration;

use writ_core::authority::TextDigest;
use writ_core::lease::State;
use writ_proto::Watched;

use super::approver::summary;
use super::{Service, WAIT_RECHECK, internal};
use crate::ServiceError;

/// The longest a watch waits for a change before it answers with the same tickets: well
/// under the listeners' 10 minutes of inactivity, so a watch never outlives its connection.
pub const WATCH_LIMIT: Duration = Duration::from_secs(240);

impl Service {
    /// The tickets waiting for a signature, in id order, and their cursor.
    pub fn waiting_tickets(&self) -> Result<Watched, ServiceError> {
        let (_, inner) = self.begin()?;
        let mut records = inner.store.tickets(State::Pending).map_err(internal)?;
        records.sort_by(|a, b| a.ticket.id.cmp(&b.ticket.id));
        let ids: Vec<String> = records.iter().map(|r| r.ticket.id.to_string()).collect();
        Ok(Watched {
            cursor: cursor(&ids),
            tickets: records.iter().map(summary).collect(),
        })
    }

    /// Waits until the tickets waiting for a signature aren't the ones `since` names (at once
    /// with no cursor, or one that names others), or [`WATCH_LIMIT`] passed: then the tickets
    /// waiting now. Pending tickets past their expiry are swept while it waits, so one that
    /// expires leaves the reply. The store is read on a blocking thread.
    pub async fn watch(&self, since: Option<&TextDigest>) -> Result<Watched, ServiceError> {
        let service = self
            .me
            .upgrade()
            .ok_or_else(|| internal("the service is gone"))?;
        let deadline = tokio::time::Instant::now() + WATCH_LIMIT;
        loop {
            // Enabled before the store is read: a change between the read and the wait still
            // wakes it.
            let notified = self.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let me = Arc::clone(&service);
            let now = tokio::task::spawn_blocking(move || me.waiting_tickets())
                .await
                .map_err(internal)??;
            if since != Some(&now.cursor) || tokio::time::Instant::now() >= deadline {
                return Ok(now);
            }
            let recheck = deadline
                .saturating_duration_since(tokio::time::Instant::now())
                .min(WAIT_RECHECK);
            tokio::select! {
                () = &mut notified => {}
                () = tokio::time::sleep(recheck) => {
                    let me = Arc::clone(&service);
                    tokio::task::spawn_blocking(move || me.sweep()).await.map_err(internal)?;
                }
            }
        }
    }
}

/// The cursor of a set of waiting tickets: the SHA-256 of their ids, in order, one per line.
fn cursor(ids: &[String]) -> TextDigest {
    TextDigest::of(&ids.join("\n"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_cursor_names_the_ids_in_order_and_nothing_else() {
        let (a, b) = ("wrt_a".to_owned(), "wrt_b".to_owned());
        assert_eq!(
            cursor(&[a.clone(), b.clone()]),
            TextDigest::of("wrt_a\nwrt_b")
        );
        assert_ne!(cursor(&[a.clone(), b.clone()]), cursor(&[b, a.clone()]));
        assert_ne!(cursor(&[a]), cursor(&[]));
        assert_eq!(cursor(&[]), TextDigest::of(""));
    }
}
