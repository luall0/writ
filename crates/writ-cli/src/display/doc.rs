//! The trusted display as a structure (M7.8): the sections and rows `writ sign` shows, each
//! row tagged with what it is (an enforced term, the agent's words, context, a change, a
//! warning), for the approval popup to style. It is written by the very calls that write the
//! terminal's text ([`Out`]), so the two never say different things; the app never reads the
//! text to find the rows, and agent text can't be made to look like a row of Writ's (it is
//! only ever in a row tagged as the agent's).

use serde::Serialize;

/// A ticket's display: its sections, in the order the terminal shows them.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Doc {
    pub sections: Vec<Section>,
}

/// One section: what it is, its title (Writ's words, ids in them cleaned), its rows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Section {
    pub kind: SectionKind,
    pub title: String,
    pub rows: Vec<Row>,
}

/// What a section is: the app places and styles each kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SectionKind {
    /// The ticket: its id, revision, state, times, what it amends, renews or revises.
    Ticket,
    /// Who asks: the session key, the caller, the agent's origin hint.
    Who,
    /// The lease's terms over every repository.
    Lease,
    /// One repository's terms.
    Repository,
    /// The agent's words: title, task, plan, estimate.
    Agent,
    /// The approver's feedback on the revision before, as the daemon recorded it.
    Feedback,
    /// The chain a renewal continues.
    Renewal,
    /// What changed since the ticket followed, or what the approver narrowed.
    Changes,
    /// The other active leases from the ticket's source.
    Others,
    /// What gets signed, whatever the agent wrote.
    Signing,
}

/// One row: its label (none for a line of its own), its value (already cleaned: one or
/// several lines), what it is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Row {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    pub value: String,
    pub tag: Tag,
    /// For a term that is a list (repos, emails, operations, branches, expected paths): its
    /// items, each cleaned as the value shows it, for the app to show one by one; none
    /// otherwise, or for a term over several repositories (its value names each).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub items: Vec<String>,
}

/// What a row is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Tag {
    /// A term the daemon enforces.
    Enforced,
    /// The agent's words: never acted on, shown as written.
    Agent,
    /// Writ's or the daemon's context: times, counts, ids.
    Context,
    /// A term's value after the change.
    Added,
    /// A term's value before the change.
    Removed,
    /// The agent's words after the change.
    AgentAdded,
    /// The agent's words before the change.
    AgentRemoved,
    /// Something to look at twice (a lease that overlaps, terms narrowed).
    Warning,
}

impl Tag {
    /// Whether the row holds the agent's words.
    #[cfg(test)]
    pub fn is_agent(self) -> bool {
        matches!(self, Self::Agent | Self::AgentAdded | Self::AgentRemoved)
    }
}

/// What the display writes: the terminal's text, and the same as a structure.
#[derive(Debug, Default)]
pub struct Out {
    pub text: String,
    pub doc: Doc,
}

impl Out {
    /// Starts a section of the structure (the text writes its own title).
    pub(crate) fn section(&mut self, kind: SectionKind, title: &str) {
        self.doc.sections.push(Section {
            kind,
            title: title.to_owned(),
            rows: Vec::new(),
        });
    }

    /// A row of the structure, in the section last started (the text writes its own).
    pub(crate) fn row(&mut self, label: Option<&str>, value: &str, tag: Tag) {
        if self.doc.sections.is_empty() {
            self.section(SectionKind::Ticket, "");
        }
        if let Some(section) = self.doc.sections.last_mut() {
            section.rows.push(Row {
                label: label.map(str::to_owned),
                value: value.to_owned(),
                tag,
                items: Vec::new(),
            });
        }
    }

    /// The items of the row last written (a list-valued term's).
    pub(crate) fn items(&mut self, items: Vec<String>) {
        if let Some(row) = self
            .doc
            .sections
            .last_mut()
            .and_then(|section| section.rows.last_mut())
        {
            row.items = items;
        }
    }
}
