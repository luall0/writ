//! Rows decoded strictly: a ticket's canonical bytes must decode and match the row, a state
//! must be one the row can be in, an approval must be complete and in its namespace.
//! Anything else is [`StoreError::Corrupt`]: fail closed.

use rusqlite::Row;
use writ_core::canonical::Canonical;
use writ_core::lease::{APPROVAL_NAMESPACE, Approval, Lease, State, TicketRecord};
use writ_core::names::TicketId;
use writ_core::ticket::Ticket;

use crate::{Result, StoreError};

/// The columns [`raw_record`] reads, in order.
pub(super) const RECORD_COLUMNS: &str =
    "id, canonical, state, feedback, approver, namespace, sshsig, feedback_by";

pub(super) fn corrupt(id: &str, why: impl std::fmt::Display) -> StoreError {
    StoreError::Corrupt {
        id: id.to_owned(),
        why: why.to_string(),
    }
}

pub(super) fn serial_to_sql(serial: u64) -> Result<i64> {
    i64::try_from(serial).map_err(|_| corrupt("certificate", "serial out of range"))
}

pub(super) struct RawRecord {
    id: String,
    canonical: Vec<u8>,
    state: String,
    feedback: Option<String>,
    feedback_by: Option<String>,
    approval: RawApproval,
}

struct RawApproval {
    approver: Option<String>,
    namespace: Option<String>,
    sshsig: Option<String>,
}

impl RawApproval {
    fn decode(self, id: &str) -> Result<Option<Approval>> {
        match (self.approver, self.namespace, self.sshsig) {
            (None, None, None) => Ok(None),
            (Some(approver), Some(namespace), Some(sshsig)) => {
                if namespace != APPROVAL_NAMESPACE {
                    return Err(corrupt(id, "approval under another namespace"));
                }
                Ok(Some(Approval {
                    approver: approver.parse().map_err(|e| corrupt(id, e))?,
                    namespace,
                    sshsig,
                }))
            }
            _ => Err(corrupt(id, "incomplete approval")),
        }
    }
}

pub(super) fn raw_record(row: &Row<'_>) -> rusqlite::Result<RawRecord> {
    Ok(RawRecord {
        id: row.get(0)?,
        canonical: row.get(1)?,
        state: row.get(2)?,
        feedback: row.get(3)?,
        feedback_by: row.get(7)?,
        approval: RawApproval {
            approver: row.get(4)?,
            namespace: row.get(5)?,
            sshsig: row.get(6)?,
        },
    })
}

impl RawRecord {
    pub(super) fn decode(self) -> Result<TicketRecord> {
        let ticket = Ticket::from_canonical(&self.canonical).map_err(|e| corrupt(&self.id, e))?;
        if ticket.id.as_str() != self.id {
            return Err(corrupt(&self.id, "the stored ticket has another id"));
        }
        let state: State = self.state.parse().map_err(|e| corrupt(&self.id, e))?;
        Ok(TicketRecord {
            ticket,
            state,
            feedback: self.feedback,
            feedback_by: self
                .feedback_by
                .map(|f| f.parse())
                .transpose()
                .map_err(|e| corrupt(&self.id, e))?,
            approval: self.approval.decode(&self.id)?,
        })
    }
}

/// The lease row `l` joined with the row of its terms in force `c`.
pub(super) fn lease_query(condition: &str) -> String {
    format!(
        "SELECT l.id, l.state, l.cert_serial, c.id, c.canonical, c.approver, c.namespace, c.sshsig
         FROM tickets l JOIN tickets c ON c.id = l.current_ticket
         WHERE {condition} AND l.cert_serial IS NOT NULL ORDER BY l.id"
    )
}

pub(super) struct RawLease {
    id: String,
    state: String,
    cert_serial: i64,
    current_id: String,
    canonical: Vec<u8>,
    approval: RawApproval,
}

pub(super) fn raw_lease(row: &Row<'_>) -> rusqlite::Result<RawLease> {
    Ok(RawLease {
        id: row.get(0)?,
        state: row.get(1)?,
        cert_serial: row.get(2)?,
        current_id: row.get(3)?,
        canonical: row.get(4)?,
        approval: RawApproval {
            approver: row.get(5)?,
            namespace: row.get(6)?,
            sshsig: row.get(7)?,
        },
    })
}

impl RawLease {
    pub(super) fn decode(self) -> Result<Lease> {
        let id: TicketId = self.id.parse().map_err(|e| corrupt(&self.id, e))?;
        let ticket = Ticket::from_canonical(&self.canonical).map_err(|e| corrupt(&self.id, e))?;
        if ticket.id.as_str() != self.current_id || ticket.lease_id() != &id {
            return Err(corrupt(&self.id, "terms in force belong to another lease"));
        }
        let state: State = self.state.parse().map_err(|e| corrupt(&self.id, e))?;
        if matches!(state, State::Pending | State::Refused | State::Applied) {
            return Err(corrupt(&self.id, format!("a lease can't be {state}")));
        }
        let approval = self
            .approval
            .decode(&self.id)?
            .ok_or_else(|| corrupt(&self.id, "a lease without an approval"))?;
        Ok(Lease {
            id,
            ticket,
            approval,
            state,
            cert_serial: u64::try_from(self.cert_serial).map_err(|e| corrupt(&self.id, e))?,
        })
    }
}
