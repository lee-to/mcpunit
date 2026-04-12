//! Shared summary view.
//!
//! [`build_report_summary`] takes a fully-scored [`Report`] and produces a
//! compact, deterministic snapshot that every reporter consumes. Sort keys:
//!
//! * `top_findings` / `findings_by_bucket` — descending score impact, then
//!   descending severity rank, then ascending `(tool_name, rule_id, message)`.
//! * `bucket_summary` — descending penalty points, then fixed display
//!   priority (security → conformance → ergonomics → metadata), then
//!   descending finding count.
//! * `review_first_tools` — descending penalty, then descending max severity,
//!   then descending finding count, then ascending tool name.
//!
//! Everything is O(n log n) in findings and allocates only when required by
//! the sort step — no intermediate buffers live past this function.

use std::collections::BTreeMap;

use crate::models::{Finding, RiskCategory, ScoreBucket, Severity};
use crate::scoring::Report;

pub const SCORE_MEANING: &str = "Deterministic CI-first quality audit based on conformance, \
security-relevant capabilities, ergonomics, and metadata hygiene.";
pub const SCORE_LIMITS: &[&str] = &[
    "Low score means more deterministic findings or higher-risk exposed surface, not malicious intent.",
    "High score means fewer deterministic findings, not a guarantee of safety.",
];
pub const MAX_SUMMARY_FINDINGS: usize = 5;
pub const MAX_REVIEW_FIRST_TOOLS: usize = 5;

#[derive(Debug, Clone)]
pub struct SummaryFinding {
    pub id: String,
    pub title: Option<String>,
    pub severity: Severity,
    pub bucket: ScoreBucket,
    pub risk_category: RiskCategory,
    pub tool_name: Option<String>,
    pub rationale: Option<String>,
    pub message: String,
    pub score_impact: u32,
}

#[derive(Debug, Clone, Default)]
pub struct SeverityCounts {
    pub info: u32,
    pub warning: u32,
    pub error: u32,
}

#[derive(Debug, Clone)]
pub struct BucketSummary {
    pub bucket: ScoreBucket,
    pub label: &'static str,
    pub finding_count: u32,
    pub penalty_points: u32,
    pub tool_names: Vec<String>,
    pub risk_categories: Vec<&'static str>,
}

#[derive(Debug, Clone)]
pub struct BucketFindingsGroup {
    pub bucket: ScoreBucket,
    pub label: &'static str,
    pub finding_count: u32,
    pub penalty_points: u32,
    pub findings: Vec<SummaryFinding>,
}

#[derive(Debug, Clone)]
pub struct ReportSummary {
    pub tool_count: usize,
    pub finding_count: usize,
    pub severity_counts: SeverityCounts,
    pub top_findings: Vec<SummaryFinding>,
    pub bucket_summary: Vec<BucketSummary>,
    pub findings_by_bucket: Vec<BucketFindingsGroup>,
    pub why_score: String,
    pub review_first_tools: Vec<String>,
    pub score_meaning: &'static str,
    pub score_limits: &'static [&'static str],
}

fn severity_rank(sev: Severity) -> i32 {
    match sev {
        Severity::Info => 0,
        Severity::Warning => 1,
        Severity::Error => 2,
    }
}

fn bucket_display_priority(bucket: ScoreBucket) -> u32 {
    match bucket {
        ScoreBucket::Security => 0,
        ScoreBucket::Conformance => 1,
        ScoreBucket::Ergonomics => 2,
        ScoreBucket::Metadata => 3,
    }
}

fn finding_sort_key(finding: &Finding) -> (i32, i32, String, String, String) {
    (
        -(finding.penalty as i32),
        -severity_rank(finding.level),
        finding.tool_name.clone().unwrap_or_default(),
        finding.rule_id.clone(),
        finding.message.clone(),
    )
}

fn to_summary_finding(finding: &Finding, rationale: Option<&str>) -> SummaryFinding {
    SummaryFinding {
        id: finding.rule_id.clone(),
        title: finding.title.clone(),
        severity: finding.level,
        bucket: finding.bucket,
        risk_category: finding.risk_category,
        tool_name: finding.tool_name.clone(),
        rationale: rationale.map(|s| s.to_string()),
        message: finding.message.clone(),
        score_impact: finding.penalty,
    }
}

pub fn build_report_summary(report: &Report) -> ReportSummary {
    let mut sorted = report.findings.clone();
    sorted.sort_by_key(finding_sort_key);

    let mut severity_counts = SeverityCounts::default();
    for f in &report.findings {
        match f.level {
            Severity::Info => severity_counts.info += 1,
            Severity::Warning => severity_counts.warning += 1,
            Severity::Error => severity_counts.error += 1,
        }
    }

    let bucket_summary = build_bucket_summary(&sorted);
    let findings_by_bucket = build_findings_by_bucket(&sorted, report, &bucket_summary);

    let top_findings: Vec<SummaryFinding> = sorted
        .iter()
        .take(MAX_SUMMARY_FINDINGS)
        .map(|f| {
            let rationale = report.rule_descriptor(&f.rule_id).map(|d| d.rationale);
            to_summary_finding(f, rationale)
        })
        .collect();

    ReportSummary {
        tool_count: report.server.tools.len(),
        finding_count: report.findings.len(),
        severity_counts,
        top_findings,
        bucket_summary: bucket_summary.clone(),
        findings_by_bucket,
        why_score: build_why_score(&bucket_summary),
        review_first_tools: build_review_first_tools(&sorted),
        score_meaning: SCORE_MEANING,
        score_limits: SCORE_LIMITS,
    }
}

fn build_bucket_summary(findings: &[Finding]) -> Vec<BucketSummary> {
    let mut bucket_count: BTreeMap<ScoreBucket, u32> = BTreeMap::new();
    let mut bucket_penalty: BTreeMap<ScoreBucket, u32> = BTreeMap::new();
    let mut bucket_tools: BTreeMap<ScoreBucket, std::collections::BTreeSet<String>> =
        BTreeMap::new();
    let mut bucket_risk_penalty: BTreeMap<ScoreBucket, BTreeMap<RiskCategory, u32>> =
        BTreeMap::new();

    for f in findings {
        *bucket_count.entry(f.bucket).or_insert(0) += 1;
        *bucket_penalty.entry(f.bucket).or_insert(0) += f.penalty;
        if let Some(name) = &f.tool_name {
            bucket_tools
                .entry(f.bucket)
                .or_default()
                .insert(name.clone());
        }
        *bucket_risk_penalty
            .entry(f.bucket)
            .or_default()
            .entry(f.risk_category)
            .or_insert(0) += f.penalty;
    }

    let mut buckets: Vec<ScoreBucket> = bucket_count.keys().copied().collect();
    buckets.sort_by_key(|b| {
        (
            -(bucket_penalty[b] as i32),
            bucket_display_priority(*b),
            -(bucket_count[b] as i32),
        )
    });

    buckets
        .into_iter()
        .map(|bucket| {
            let risk_map = bucket_risk_penalty.remove(&bucket).unwrap_or_default();
            let mut risks: Vec<(RiskCategory, u32)> = risk_map.into_iter().collect();
            risks.sort_by(|a, b| {
                let by_penalty = b.1.cmp(&a.1);
                if by_penalty != std::cmp::Ordering::Equal {
                    return by_penalty;
                }
                a.0.label().cmp(b.0.label())
            });
            let risk_labels: Vec<&'static str> = risks.iter().map(|(r, _)| r.label()).collect();

            let tools: Vec<String> = bucket_tools
                .remove(&bucket)
                .unwrap_or_default()
                .into_iter()
                .collect();

            BucketSummary {
                bucket,
                label: bucket.label(),
                finding_count: bucket_count[&bucket],
                penalty_points: bucket_penalty[&bucket],
                tool_names: tools,
                risk_categories: risk_labels,
            }
        })
        .collect()
}

fn build_findings_by_bucket(
    findings: &[Finding],
    report: &Report,
    bucket_summary: &[BucketSummary],
) -> Vec<BucketFindingsGroup> {
    let mut grouped: BTreeMap<ScoreBucket, Vec<SummaryFinding>> = BTreeMap::new();
    for f in findings {
        let rationale = report.rule_descriptor(&f.rule_id).map(|d| d.rationale);
        grouped
            .entry(f.bucket)
            .or_default()
            .push(to_summary_finding(f, rationale));
    }
    bucket_summary
        .iter()
        .map(|info| BucketFindingsGroup {
            bucket: info.bucket,
            label: info.label,
            finding_count: info.finding_count,
            penalty_points: info.penalty_points,
            findings: grouped.remove(&info.bucket).unwrap_or_default(),
        })
        .collect()
}

fn build_why_score(bucket_summary: &[BucketSummary]) -> String {
    if bucket_summary.is_empty() {
        return "No deterministic issues were detected in the current server surface.".to_string();
    }
    let descriptions: Vec<String> = bucket_summary.iter().take(2).map(describe_bucket).collect();
    match descriptions.len() {
        1 => format!("Score is driven mainly by {}.", descriptions[0]),
        _ => format!(
            "Score is driven mainly by {} and {}.",
            descriptions[0], descriptions[1]
        ),
    }
}

fn describe_bucket(info: &BucketSummary) -> String {
    let name = info.label;
    let risk_categories: Vec<&&'static str> = info.risk_categories.iter().take(2).collect();
    if name == "security" && !risk_categories.is_empty() {
        if risk_categories.len() == 1 {
            return format!("security findings in {}", risk_categories[0]);
        }
        return format!(
            "security findings in {} and {}",
            risk_categories[0], risk_categories[1]
        );
    }
    format!("{name} findings")
}

fn build_review_first_tools(findings: &[Finding]) -> Vec<String> {
    let mut penalties: BTreeMap<String, u32> = BTreeMap::new();
    let mut counts: BTreeMap<String, u32> = BTreeMap::new();
    let mut sev_ranks: BTreeMap<String, i32> = BTreeMap::new();

    for f in findings {
        let Some(name) = &f.tool_name else { continue };
        *penalties.entry(name.clone()).or_insert(0) += f.penalty;
        *counts.entry(name.clone()).or_insert(0) += 1;
        let rank = sev_ranks.entry(name.clone()).or_insert(0);
        let new_rank = severity_rank(f.level);
        if new_rank > *rank {
            *rank = new_rank;
        }
    }

    let mut ordered: Vec<String> = penalties.keys().cloned().collect();
    ordered.sort_by_key(|name| {
        (
            -(penalties[name] as i32),
            -sev_ranks[name],
            -(counts[name] as i32),
            name.clone(),
        )
    });
    ordered.truncate(MAX_REVIEW_FIRST_TOOLS);
    ordered
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{FindingCategory, NormalizedServer, NormalizedTool};
    use std::collections::BTreeMap as Map;

    fn finding(rule: &str, tool: &str, bucket: ScoreBucket, severity: Severity) -> Finding {
        Finding {
            rule_id: rule.to_string(),
            level: severity,
            title: Some("t".to_string()),
            message: format!("{rule} on {tool}"),
            category: FindingCategory::ToolIdentity,
            risk_category: RiskCategory::MetadataHygiene,
            bucket,
            evidence: vec![],
            penalty: severity.score_impact(),
            tool_name: Some(tool.to_string()),
            metadata: Map::new(),
        }
    }

    fn report_with(findings: Vec<Finding>) -> Report {
        let mut server = NormalizedServer::new("target");
        server.tools.push(NormalizedTool {
            name: "t".to_string(),
            description: None,
            input_schema: serde_json::json!({}),
            metadata: Map::new(),
        });
        let score = crate::scoring::ScoreBreakdown::from_findings(&findings, 100);
        Report {
            server,
            findings,
            score,
            rule_descriptors: Vec::new(),
            generated_at: chrono::Utc::now(),
            schema_version: "1".to_string(),
            toolkit_version: "0".to_string(),
        }
    }

    #[test]
    fn empty_report_has_default_summary() {
        let summary = build_report_summary(&report_with(vec![]));
        assert_eq!(summary.finding_count, 0);
        assert!(summary.bucket_summary.is_empty());
        assert!(summary.why_score.starts_with("No deterministic"));
    }

    #[test]
    fn findings_are_sorted_by_impact() {
        let findings = vec![
            finding("low", "a", ScoreBucket::Metadata, Severity::Info),
            finding("high", "b", ScoreBucket::Security, Severity::Error),
            finding("mid", "c", ScoreBucket::Conformance, Severity::Warning),
        ];
        let summary = build_report_summary(&report_with(findings));
        assert_eq!(summary.top_findings[0].id, "high");
        assert_eq!(summary.top_findings[1].id, "mid");
    }

    #[test]
    fn bucket_summary_prioritises_security_ties() {
        let findings = vec![
            finding("a", "x", ScoreBucket::Conformance, Severity::Warning),
            finding("b", "y", ScoreBucket::Security, Severity::Warning),
        ];
        let summary = build_report_summary(&report_with(findings));
        assert_eq!(summary.bucket_summary[0].bucket, ScoreBucket::Security);
    }

    #[test]
    fn review_first_tools_sort_by_penalty() {
        let findings = vec![
            finding("a", "one", ScoreBucket::Security, Severity::Error),
            finding("b", "two", ScoreBucket::Security, Severity::Warning),
        ];
        let summary = build_report_summary(&report_with(findings));
        assert_eq!(summary.review_first_tools, vec!["one", "two"]);
    }
}
