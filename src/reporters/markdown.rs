//! Markdown summary reporter — designed for GitHub step summaries.
//!
//! Produces a compact markdown document with a score headline, a
//! category score table, and a bullet list of findings grouped by bucket.
//! Shares [`build_report_summary`](crate::reporters::summary) with the
//! terminal and JSON reporters so the three views never drift.

use crate::models::ScoreBucket;
use crate::reporters::summary::build_report_summary;
use crate::reporters::Reporter;
use crate::scoring::Report;

pub struct MarkdownReporter;

impl Reporter for MarkdownReporter {
    fn id(&self) -> &'static str {
        "markdown"
    }

    fn render(&self, report: &Report) -> String {
        let summary = build_report_summary(report);
        let mut out = String::new();

        out.push_str(&format!(
            "# {} Audit — {}\n\n",
            crate::PRODUCT_NAME,
            report
                .server
                .name
                .as_deref()
                .unwrap_or(report.server.target.as_str())
        ));
        out.push_str(&format!(
            "**Total score:** `{} / {}`  \n",
            report.score.total_score, report.score.max_score
        ));
        out.push_str(&format!(
            "**Findings:** {total} (error: {err}, warning: {warn}, info: {info})  \n",
            total = summary.finding_count,
            err = summary.severity_counts.error,
            warn = summary.severity_counts.warning,
            info = summary.severity_counts.info,
        ));
        out.push_str(&format!("**Tools discovered:** {}\n\n", summary.tool_count));

        out.push_str("## Category Scores\n\n");
        out.push_str("| Bucket | Score | Findings | Penalty |\n");
        out.push_str("| --- | --- | --- | --- |\n");
        for bucket in ScoreBucket::ALL {
            let b = report.score.breakdown_for(*bucket);
            out.push_str(&format!(
                "| {} | {}/{} | {} | {} |\n",
                bucket.as_str(),
                b.score,
                b.max_score,
                b.finding_count,
                b.penalty_points
            ));
        }
        out.push('\n');

        out.push_str("## Findings By Bucket\n\n");
        if summary.findings_by_bucket.is_empty() {
            out.push_str("_No deterministic findings._\n\n");
        } else {
            for group in &summary.findings_by_bucket {
                out.push_str(&format!(
                    "### {} ({} finding{}, penalty: {})\n\n",
                    group.label,
                    group.finding_count,
                    if group.finding_count == 1 { "" } else { "s" },
                    group.penalty_points
                ));
                for finding in &group.findings {
                    let subject =
                        match (finding.tool_name.as_deref(), finding.prompt_name.as_deref()) {
                            (Some(t), _) => format!(" `[tool:{t}]`"),
                            (None, Some(p)) => format!(" `[prompt:{p}]`"),
                            (None, None) => String::new(),
                        };
                    out.push_str(&format!(
                        "- **{}** `{}`{}: {}\n",
                        finding.severity.as_str().to_ascii_uppercase(),
                        finding.id,
                        subject,
                        finding.message
                    ));
                }
                out.push('\n');
            }
        }

        out.push_str("## Limitations\n\n");
        for note in summary.score_limits {
            out.push_str(&format!("- {note}\n"));
        }

        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{NormalizedServer, NormalizedTool};
    use crate::scoring::scan;

    fn sample_report() -> Report {
        let mut server = NormalizedServer::new("stdio:test");
        server.tools.push(NormalizedTool {
            name: "helper".to_string(),
            description: None,
            input_schema: serde_json::json!({}),
            metadata: Default::default(),
        });
        scan(server, 100)
    }

    #[test]
    fn render_contains_category_score_table() {
        let out = MarkdownReporter.render(&sample_report());
        assert!(out.contains("| Bucket | Score | Findings | Penalty |"));
        assert!(out.contains("| conformance |"));
        assert!(out.contains("| security |"));
    }

    #[test]
    fn render_includes_total_score() {
        let out = MarkdownReporter.render(&sample_report());
        assert!(out.contains("**Total score:**"));
    }
}
