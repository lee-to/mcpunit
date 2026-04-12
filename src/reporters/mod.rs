//! Report rendering layer.
//!
//! Each reporter implements [`Reporter::render`] and takes a fully-scored
//! [`crate::scoring::Report`]. The shared [`summary`] module builds the
//! `ReportSummary` view that JSON, SARIF, terminal, and Markdown reporters
//! all consume.

use crate::scoring::Report;

pub mod json;
pub mod markdown;
pub mod sarif;
pub mod summary;
pub mod terminal;

pub use json::JsonReporter;
pub use markdown::MarkdownReporter;
pub use sarif::SarifReporter;
pub use terminal::TerminalReporter;

/// Common interface for every reporter. Reporters are stateless — they
/// simply transform a [`Report`] into a string.
pub trait Reporter {
    /// Stable reporter identifier used by the CLI (`json`, `sarif`, ...).
    fn id(&self) -> &'static str;

    /// Render the report to a string.
    fn render(&self, report: &Report) -> String;
}
