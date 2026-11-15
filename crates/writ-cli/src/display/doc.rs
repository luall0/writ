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
    /// A repository's section: its name (cleaned), for the app to title its card without
    /// reading the title (M7.9.5).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repo: Option<String>,
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
    /// The time the row shows (RFC 3339, UTC), for the app to say how far it is ("in 2h")
    /// beside the clock time; none for a row that shows no time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub at: Option<String>,
    /// For the expected paths: the same items as a tree of folders ([`path_tree`]), for the
    /// app to show as a file browser without splitting a value itself; none otherwise.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tree: Vec<Node>,
    /// A change to a per-repository term over several repositories: the repository it is in.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repo: Option<String>,
}

/// One node of a path tree: a folder (its name ends with `/`, and may hold several
/// segments merged) or a leaf (the rest of one path). Every path is the names on its way
/// down, joined as they are: nothing is added, dropped or reordered within a path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Node {
    pub name: String,
    pub kind: NodeKind,
    /// The paths under a folder (1 for a leaf).
    pub paths: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub children: Vec<Node>,
}

/// What a node is: the app picks its icon and badge from this, never from the name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeKind {
    Folder,
    /// A leaf with no glob character: one file.
    File,
    /// A leaf with a glob character (`*`, `?`, `[`, `{`): several files may match.
    Pattern,
    /// The leaf `**`: everything under its folder.
    Everything,
}

/// The paths (each already [`clean`](super::clean)ed, as the row's items) as a tree: split
/// at each `/`, folders first then leaves, each by name; a folder holding only one folder,
/// and nothing else, merged with it into one node (`writ-integration/tests/`). Built from
/// the items alone, so the leaves are exactly the items: [`leaves`] gives them back.
pub fn path_tree(items: &[String]) -> Vec<Node> {
    #[derive(Default)]
    struct Dir {
        dirs: std::collections::BTreeMap<String, Dir>,
        leaves: std::collections::BTreeSet<String>,
    }
    let mut root = Dir::default();
    for item in items {
        let mut segments: Vec<&str> = item.split('/').collect();
        let leaf = segments.pop().unwrap_or_default();
        let mut at = &mut root;
        for segment in segments {
            at = at.dirs.entry(format!("{segment}/")).or_default();
        }
        at.leaves.insert(leaf.to_owned());
    }
    fn nodes(dir: Dir) -> Vec<Node> {
        let mut out = Vec::new();
        for (name, sub) in dir.dirs {
            let mut name = name;
            let mut sub = sub;
            // One folder and nothing else: merged, its name carried whole.
            while sub.leaves.is_empty() && sub.dirs.len() == 1 {
                let Some((inner, below)) = sub.dirs.pop_first() else {
                    break;
                };
                name.push_str(&inner);
                sub = below;
            }
            let children = nodes(sub);
            let paths = children.iter().map(|c| c.paths).sum();
            out.push(Node {
                name,
                kind: NodeKind::Folder,
                paths,
                children,
            });
        }
        for leaf in dir.leaves {
            let kind = if leaf == "**" {
                NodeKind::Everything
            } else if leaf.contains(['*', '?', '[', '{']) {
                NodeKind::Pattern
            } else {
                NodeKind::File
            };
            out.push(Node {
                name: leaf,
                kind,
                paths: 1,
                children: Vec::new(),
            });
        }
        out
    }
    nodes(root)
}

/// The paths a tree holds, each the names on its way down joined: [`path_tree`] undone.
#[cfg(test)]
pub fn leaves(tree: &[Node]) -> Vec<String> {
    fn walk(nodes: &[Node], prefix: &str, out: &mut Vec<String>) {
        for node in nodes {
            let name = format!("{prefix}{}", node.name);
            match node.kind {
                NodeKind::Folder => walk(&node.children, &name, out),
                _ => out.push(name),
            }
        }
    }
    let mut out = Vec::new();
    walk(tree, "", &mut out);
    out
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
            repo: None,
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
                at: None,
                tree: Vec::new(),
                repo: None,
            });
        }
    }

    /// The repository the section last started is (a repository's section).
    pub(crate) fn section_repo(&mut self, repo: &str) {
        if let Some(section) = self.doc.sections.last_mut() {
            section.repo = Some(repo.to_owned());
        }
    }

    /// The repository the row last written is about, when it is one's (a change across
    /// several repositories).
    pub(crate) fn repo(&mut self, repo: Option<&str>) {
        if let (Some(row), Some(repo)) = (self.last_row(), repo) {
            row.repo = Some(repo.to_owned());
        }
    }

    /// The time the row last written shows.
    pub(crate) fn at(&mut self, at: writ_core::units::Timestamp) {
        if let Some(row) = self.last_row() {
            row.at = Some(at.to_string());
        }
    }

    /// The row last written's items as a path tree ([`path_tree`]): the expected paths.
    pub(crate) fn tree(&mut self) {
        if let Some(row) = self.last_row() {
            row.tree = path_tree(&row.items);
        }
    }

    fn last_row(&mut self) -> Option<&mut Row> {
        self.doc
            .sections
            .last_mut()
            .and_then(|section| section.rows.last_mut())
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
