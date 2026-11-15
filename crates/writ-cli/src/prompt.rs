//! Every question `writ` asks on a terminal (M7.9.5): a select moved with the arrow keys and
//! filtered by typing, a multi-select (space picks, Enter ends), text checked as it is typed,
//! a confirm, a pause; colour unless `NO_COLOR` is set. Without a terminal (stdin or stderr
//! not one, or `TERM=dumb`) each falls back to the plain line prompt `writ` always had, so
//! scripts and the variables that answer work as before.
//!
//! Everything shown is [`clean`]ed here, whoever passed it: a question, a help line, an option
//! (a name from the policy, a host key a remote sent). What is typed is the operator's own.
//! Passphrases and secrets are never asked here: `writ_crypto::passphrase` reads them into
//! memory it wipes.

use std::io::{BufRead as _, IsTerminal as _, Write as _};

use anyhow::Context as _;
use inquire::error::InquireError;
use inquire::ui::{Color, RenderConfig, StyleSheet, Styled};
use inquire::validator::Validation;

use crate::display::clean;

/// Whether the questions are widgets: stdin and stderr (where they are drawn) terminals, and a
/// terminal that can draw them.
pub fn widgets() -> bool {
    std::io::stdin().is_terminal()
        && std::io::stderr().is_terminal()
        && std::env::var_os("TERM").is_none_or(|t| t != "dumb")
}

/// One option of a select: what it gives, and how it is shown (already readable: cleaned again
/// here).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Choice {
    pub value: String,
    pub label: String,
}

impl Choice {
    pub fn new(value: impl Into<String>, label: impl Into<String>) -> Self {
        Self {
            value: value.into(),
            label: label.into(),
        }
    }
}

impl std::fmt::Display for Choice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.label)
    }
}

/// What came of a question.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer<T> {
    Given(T),
    /// Esc, or the end of the input: nothing chosen.
    Cancelled,
}

/// The colours, or none with `NO_COLOR` (any value, <https://no-color.org>).
fn style() -> RenderConfig<'static> {
    style_for(std::env::var_os("NO_COLOR").is_some())
}

fn style_for(no_color: bool) -> RenderConfig<'static> {
    if no_color {
        return RenderConfig::empty()
            .with_prompt_prefix(Styled::new("?"))
            .with_answered_prompt_prefix(Styled::new(">"))
            .with_highlighted_option_prefix(Styled::new(">"))
            .with_selected_checkbox(Styled::new("[x]"))
            .with_unselected_checkbox(Styled::new("[ ]"));
    }
    RenderConfig::default_colored()
        .with_prompt_prefix(Styled::new("?").with_fg(Color::LightCyan))
        .with_answered_prompt_prefix(Styled::new(">").with_fg(Color::LightGreen))
        .with_help_message(StyleSheet::new().with_fg(Color::DarkGrey))
        .with_highlighted_option_prefix(Styled::new("›").with_fg(Color::LightCyan))
}

/// An answer that ends the question: Esc and the end of the input cancel; Ctrl-C stops `writ`
/// as it always did; anything else is an error.
fn given<T>(result: Result<T, InquireError>) -> anyhow::Result<Answer<T>> {
    match result {
        Ok(value) => Ok(Answer::Given(value)),
        Err(InquireError::OperationCanceled) => Ok(Answer::Cancelled),
        Err(InquireError::OperationInterrupted) => anyhow::bail!("interrupted: nothing was done"),
        Err(InquireError::NotTTY) => Ok(Answer::Cancelled),
        Err(other) => Err(other).context("cannot ask on the terminal"),
    }
}

/// A line read from stdin, without its end (the plain prompts).
pub fn line() -> anyhow::Result<String> {
    let mut line = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut line)
        .context("cannot read the answer")?;
    Ok(line.trim().to_owned())
}

fn flush() -> anyhow::Result<()> {
    std::io::stdout()
        .flush()
        .context("cannot write to the terminal")
}

/// One option among `choices`, the cursor first on `start`; typing filters them. Plainly: the
/// options listed, their value typed (Enter: `start`'s).
pub fn select(
    question: &str,
    help: &str,
    choices: &[Choice],
    start: usize,
) -> anyhow::Result<Answer<String>> {
    anyhow::ensure!(
        !choices.is_empty(),
        "nothing to choose from for {}",
        clean(question)
    );
    let shown: Vec<Choice> = choices
        .iter()
        .map(|c| Choice::new(c.value.clone(), clean(&c.label)))
        .collect();
    if !widgets() {
        let keeps = shown
            .get(start)
            .map(|c| c.value.clone())
            .unwrap_or_default();
        let listed: Vec<&str> = shown.iter().map(|c| c.value.as_str()).collect();
        print!(
            "{} ({}: {}) [{}]: ",
            clean(question),
            clean(help),
            listed.join(", "),
            clean(&keeps)
        );
        flush()?;
        let typed = line()?;
        return Ok(Answer::Given(if typed.is_empty() { keeps } else { typed }));
    }
    let answer = inquire::Select::new(&clean(question), shown)
        .with_help_message(&clean(help))
        .with_starting_cursor(start.min(choices.len().saturating_sub(1)))
        .with_page_size(10)
        .with_render_config(style())
        .prompt();
    Ok(match given(answer)? {
        Answer::Given(choice) => Answer::Given(choice.value),
        Answer::Cancelled => Answer::Cancelled,
    })
}

/// Some options among `choices`, `chosen` ticked at first: space ticks the one under the cursor,
/// typing filters (cleared after each tick), Enter ends. Plainly: the values typed, separated by
/// commas (Enter: the ticked ones).
pub fn multi(
    question: &str,
    help: &str,
    choices: &[Choice],
    chosen: &[usize],
) -> anyhow::Result<Answer<Vec<String>>> {
    anyhow::ensure!(
        !choices.is_empty(),
        "nothing to choose from for {}",
        clean(question)
    );
    let shown: Vec<Choice> = choices
        .iter()
        .map(|c| Choice::new(c.value.clone(), clean(&c.label)))
        .collect();
    if !widgets() {
        let keeps: Vec<String> = chosen
            .iter()
            .filter_map(|i| shown.get(*i).map(|c| c.value.clone()))
            .collect();
        let listed: Vec<&str> = shown.iter().map(|c| c.value.as_str()).collect();
        print!(
            "{} ({}: {}) [{}]: ",
            clean(question),
            clean(help),
            listed.join(", "),
            clean(&keeps.join(","))
        );
        flush()?;
        let typed = line()?;
        if typed.is_empty() {
            return Ok(Answer::Given(keeps));
        }
        return Ok(Answer::Given(
            typed
                .split(',')
                .map(|v| v.trim().to_owned())
                .filter(|v| !v.is_empty())
                .collect(),
        ));
    }
    let answer = inquire::MultiSelect::new(&clean(question), shown)
        .with_help_message(&format!(
            "{} · ↑↓ move, space ticks, type to filter, Enter ends",
            clean(help)
        ))
        .with_default(chosen)
        .with_keep_filter(false)
        .with_page_size(10)
        .with_render_config(style())
        .prompt();
    Ok(match given(answer)? {
        Answer::Given(picked) => Answer::Given(picked.into_iter().map(|c| c.value).collect()),
        Answer::Cancelled => Answer::Cancelled,
    })
}

/// A value typed, `check` saying why one isn't accepted as it is typed (it is asked again).
/// `default` is shown greyed where the answer goes; Enter on nothing gives an empty answer, the
/// caller's to read as keeping it (as the plain prompt `question (help) [default]: ` always
/// did).
pub fn text(
    question: &str,
    help: &str,
    default: Option<&str>,
    check: impl Fn(&str) -> Result<(), String> + Clone + 'static,
) -> anyhow::Result<Answer<String>> {
    if !widgets() {
        match default {
            Some(keeps) => print!("{} ({}) [{}]: ", clean(question), clean(help), clean(keeps)),
            None => print!("{} ({}): ", clean(question), clean(help)),
        }
        flush()?;
        return Ok(Answer::Given(line()?));
    }
    let shown_default = default.map(clean);
    let validator = move |typed: &str| {
        Ok(match check(typed) {
            Ok(()) => Validation::Valid,
            Err(why) => Validation::Invalid(clean(&why).into()),
        })
    };
    let (question, help) = (clean(question), clean(help));
    let mut prompt = inquire::Text::new(&question)
        .with_help_message(&help)
        .with_validator(validator)
        .with_render_config(style());
    if let Some(keeps) = &shown_default {
        prompt = prompt.with_placeholder(keeps);
    }
    given(prompt.prompt())
}

/// `question`: yes or no, no unless `y` or `yes` (any case) is typed; Esc and the end of the
/// input are no. The one way a "Sign …?" is asked on a terminal.
pub fn confirm(question: &str) -> anyhow::Result<bool> {
    if !widgets() {
        print!("{} [y/N] ", clean(question));
        flush()?;
        return Ok(crate::approver::signs(&line()?));
    }
    let answer = inquire::Text::new(&clean(question))
        .with_placeholder("y/N")
        .with_help_message("y or yes signs; anything else, Enter or Esc signs nothing")
        .with_render_config(style())
        .prompt();
    Ok(match given(answer)? {
        Answer::Given(typed) => crate::approver::signs(&typed),
        Answer::Cancelled => false,
    })
}

/// Waits for Enter (`message` says what then happens); Esc: false, nothing done.
pub fn pause(message: &str) -> anyhow::Result<bool> {
    if !widgets() {
        print!("{} ", clean(message));
        flush()?;
        line()?;
        return Ok(true);
    }
    let answer = inquire::Text::new(&clean(message))
        .with_help_message("Enter goes on, Esc stops here")
        .with_render_config(style())
        .prompt();
    Ok(matches!(given(answer)?, Answer::Given(_)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_choice_shows_its_label_and_gives_its_value() {
        let c = Choice::new("se-cryptokit", "se-cryptokit (p256)");
        assert_eq!(c.to_string(), "se-cryptokit (p256)");
        assert_eq!(c.value, "se-cryptokit");
    }

    #[test]
    fn interruption_is_an_error_and_cancelling_chooses_nothing() {
        assert_eq!(
            given::<u8>(Err(InquireError::OperationCanceled)).unwrap(),
            Answer::Cancelled
        );
        assert_eq!(
            given::<u8>(Err(InquireError::NotTTY)).unwrap(),
            Answer::Cancelled
        );
        assert_eq!(given(Ok(3_u8)).unwrap(), Answer::Given(3));
        let err = given::<u8>(Err(InquireError::OperationInterrupted)).unwrap_err();
        assert_eq!(err.to_string(), "interrupted: nothing was done");
    }

    #[test]
    fn no_color_draws_no_colour() {
        let plain = style_for(true);
        for styled in [
            plain.prompt_prefix,
            plain.highlighted_option_prefix,
            plain.selected_checkbox,
        ] {
            assert_eq!(styled.style.fg, None, "{}", styled.content);
            assert_eq!(styled.style.bg, None, "{}", styled.content);
        }
        assert_eq!(plain.help_message.fg, None);
        // A question answered reads apart from one being typed: `>`, not `?`.
        assert_eq!(plain.answered_prompt_prefix.content, ">");
        assert_eq!(plain.prompt_prefix.content, "?");
        assert!(style_for(false).prompt_prefix.style.fg.is_some());
    }

    /// Nothing a remote or the policy holds reaches the terminal raw: the labels a select draws
    /// are cleaned, however they were built.
    #[test]
    fn a_hostile_label_is_cleaned_before_it_is_drawn() {
        let hostile = Choice::new("x", "host\u{1b}[2J\u{202e}key");
        let shown = Choice::new(hostile.value.clone(), clean(&hostile.label));
        assert_eq!(shown.label, "host\\u{1b}[2J\\u{202e}key");
        assert!(!shown.label.chars().any(writ_core::text::is_hidden_char));
    }
}
