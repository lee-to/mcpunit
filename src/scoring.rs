//! Deterministic scoring engine.
//!
//! Deterministic scoring engine + the relevant parts of
//! `ScoreBreakdown.from_findings`. The engine is deliberately dumb — walk the
//! rule registry, collect findings, group penalties by rule id and by score
//! bucket, and produce a [`Report`] for the reporters to serialise.
//!
//! Byte-parity notes:
//!
//! * Per-rule penalties are tracked in a [`BTreeMap`] keyed by rule id. The scoring contract
//!   uses insertion-order dicts but accesses them via a dict comprehension
//!   that happens to walk rule definition order — see the JSON reporter for
//!   the exact trick we mirror there.
//! * Category-level penalties are pre-populated for **every** [`ScoreBucket`]
//!   variant, even when that bucket has zero findings. the contract requires this
//!   via `CategoryScoreBreakdown` validation; we replicate it so the JSON
//!   output always has four category entries in the same order.

use std::collections::BTreeMap;

use crate::models::{Finding, NormalizedServer, ScoreBucket};
use crate::rules::{Rule, REGISTRY};

pub const DEFAULT_MAX_SCORE: u32 = 100;

/// Per-category scoring data. Per-category scoring data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CategoryScoreBreakdown {
    pub category: ScoreBucket,
    pub max_score: u32,
    pub penalty_points: u32,
    pub score: u32,
    pub finding_count: u32,
    /// `rule_id → penalty points` for every rule that contributed findings
    /// to this bucket. Kept in insertion order (first-seen wins).
    pub rule_penalties: Vec<(String, u32)>,
}

/// Top-level score breakdown for a report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScoreBreakdown {
    pub max_score: u32,
    pub total_penalty_points: u32,
    pub total_score: u32,
    /// One entry per [`ScoreBucket`], in declaration order (on-wire order).
    pub category_breakdown: Vec<CategoryScoreBreakdown>,
    /// Aggregate per-rule penalties across every bucket, in insertion order.
    pub rule_penalties: Vec<(String, u32)>,
}

impl ScoreBreakdown {
    /// Build a score breakdown from raw findings.
    pub fn from_findings(findings: &[Finding], max_score: u32) -> Self {
        let mut rule_order: Vec<String> = Vec::new();
        let mut rule_totals: BTreeMap<String, u32> = BTreeMap::new();

        // Per-bucket trackers — always pre-populated for every variant.
        let mut bucket_penalty: BTreeMap<ScoreBucket, u32> = BTreeMap::new();
        let mut bucket_count: BTreeMap<ScoreBucket, u32> = BTreeMap::new();
        let mut bucket_rule_order: BTreeMap<ScoreBucket, Vec<String>> = BTreeMap::new();
        let mut bucket_rule_penalty: BTreeMap<ScoreBucket, BTreeMap<String, u32>> = BTreeMap::new();
        for bucket in ScoreBucket::ALL {
            bucket_penalty.insert(*bucket, 0);
            bucket_count.insert(*bucket, 0);
            bucket_rule_order.insert(*bucket, Vec::new());
            bucket_rule_penalty.insert(*bucket, BTreeMap::new());
        }

        for finding in findings {
            if !rule_totals.contains_key(&finding.rule_id) {
                rule_order.push(finding.rule_id.clone());
            }
            *rule_totals.entry(finding.rule_id.clone()).or_insert(0) += finding.penalty;

            *bucket_penalty.entry(finding.bucket).or_insert(0) += finding.penalty;
            *bucket_count.entry(finding.bucket).or_insert(0) += 1;

            let order = bucket_rule_order.get_mut(&finding.bucket).unwrap();
            if !order.contains(&finding.rule_id) {
                order.push(finding.rule_id.clone());
            }
            let penalties = bucket_rule_penalty.get_mut(&finding.bucket).unwrap();
            *penalties.entry(finding.rule_id.clone()).or_insert(0) += finding.penalty;
        }

        let total_penalty_points: u32 = rule_totals.values().sum();
        let total_score = max_score.saturating_sub(total_penalty_points);

        let rule_penalties: Vec<(String, u32)> = rule_order
            .iter()
            .map(|id| (id.clone(), rule_totals[id]))
            .collect();

        let category_breakdown: Vec<CategoryScoreBreakdown> = ScoreBucket::ALL
            .iter()
            .copied()
            .map(|bucket| {
                let penalty_points = bucket_penalty[&bucket];
                let finding_count = bucket_count[&bucket];
                let order = &bucket_rule_order[&bucket];
                let penalties = &bucket_rule_penalty[&bucket];
                let rule_penalties = order.iter().map(|id| (id.clone(), penalties[id])).collect();
                CategoryScoreBreakdown {
                    category: bucket,
                    max_score,
                    penalty_points,
                    score: max_score.saturating_sub(penalty_points),
                    finding_count,
                    rule_penalties,
                }
            })
            .collect();

        Self {
            max_score,
            total_penalty_points,
            total_score,
            category_breakdown,
            rule_penalties,
        }
    }

    pub fn breakdown_for(&self, bucket: ScoreBucket) -> &CategoryScoreBreakdown {
        self.category_breakdown
            .iter()
            .find(|b| b.category == bucket)
            .expect("category_breakdown always contains every bucket")
    }
}

/// Static metadata describing a rule, suitable for report serialisation.
#[derive(Debug, Clone)]
pub struct RuleDescriptor {
    pub rule_id: &'static str,
    pub title: &'static str,
    pub rationale: &'static str,
    pub severity: crate::models::Severity,
    pub category: crate::models::FindingCategory,
    pub risk_category: crate::models::RiskCategory,
    pub bucket: ScoreBucket,
    pub score_impact: u32,
    pub tags: &'static [&'static str],
}

impl RuleDescriptor {
    pub fn from_rule(rule: &'static dyn Rule) -> Self {
        let severity = rule.severity();
        Self {
            rule_id: rule.id(),
            title: rule.title(),
            rationale: rule.rationale(),
            severity,
            category: rule.category(),
            risk_category: rule.risk_category(),
            bucket: rule.bucket(),
            score_impact: severity.score_impact(),
            tags: rule.tags(),
        }
    }
}

/// Report produced by the scoring engine and consumed by reporters.
#[derive(Debug, Clone)]
pub struct Report {
    pub server: NormalizedServer,
    pub findings: Vec<Finding>,
    pub score: ScoreBreakdown,
    /// Rule metadata keyed by `rule_id`, preserving registry order.
    pub rule_descriptors: Vec<RuleDescriptor>,
    pub generated_at: chrono::DateTime<chrono::Utc>,
    pub schema_version: String,
    pub toolkit_version: String,
}

impl Report {
    pub fn finding_count(&self) -> usize {
        self.findings.len()
    }

    pub fn rule_descriptor(&self, rule_id: &str) -> Option<&RuleDescriptor> {
        self.rule_descriptors.iter().find(|r| r.rule_id == rule_id)
    }

    pub fn total_score(&self) -> u32 {
        self.score.total_score
    }
}

/// Run every rule in the static registry against `server` and build a report.
pub fn scan(server: NormalizedServer, max_score: u32) -> Report {
    let mut findings: Vec<Finding> = Vec::new();
    for rule in REGISTRY.iter() {
        findings.extend(rule.evaluate(&server));
    }
    let score = ScoreBreakdown::from_findings(&findings, max_score);
    let rule_descriptors: Vec<RuleDescriptor> = REGISTRY
        .iter()
        .copied()
        .map(RuleDescriptor::from_rule)
        .collect();

    Report {
        server,
        findings,
        score,
        rule_descriptors,
        generated_at: chrono::Utc::now(),
        schema_version: crate::REPORT_SCHEMA_VERSION.to_string(),
        toolkit_version: crate::PACKAGE_VERSION.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{FindingCategory, NormalizedTool, RiskCategory, Severity};
    use std::collections::BTreeMap;

    fn finding(rule: &str, bucket: ScoreBucket, penalty: u32) -> Finding {
        Finding {
            rule_id: rule.to_string(),
            level: Severity::Warning,
            title: Some("t".to_string()),
            message: "m".to_string(),
            category: FindingCategory::ToolIdentity,
            risk_category: RiskCategory::MetadataHygiene,
            bucket,
            evidence: vec!["e".to_string()],
            penalty,
            tool_name: Some("tool".to_string()),
            metadata: BTreeMap::new(),
        }
    }

    #[test]
    fn empty_findings_give_max_score() {
        let breakdown = ScoreBreakdown::from_findings(&[], 100);
        assert_eq!(breakdown.total_score, 100);
        assert_eq!(breakdown.total_penalty_points, 0);
        assert_eq!(breakdown.category_breakdown.len(), ScoreBucket::ALL.len());
        for category in &breakdown.category_breakdown {
            assert_eq!(category.score, 100);
            assert_eq!(category.penalty_points, 0);
            assert_eq!(category.finding_count, 0);
        }
    }

    #[test]
    fn findings_accumulate_by_bucket_and_rule() {
        let findings = vec![
            finding("a", ScoreBucket::Security, 20),
            finding("a", ScoreBucket::Security, 20),
            finding("b", ScoreBucket::Ergonomics, 10),
        ];
        let breakdown = ScoreBreakdown::from_findings(&findings, 100);
        assert_eq!(breakdown.total_penalty_points, 50);
        assert_eq!(breakdown.total_score, 50);

        let security = breakdown.breakdown_for(ScoreBucket::Security);
        assert_eq!(security.penalty_points, 40);
        assert_eq!(security.finding_count, 2);
        assert_eq!(security.rule_penalties, vec![("a".to_string(), 40)]);

        let ergonomics = breakdown.breakdown_for(ScoreBucket::Ergonomics);
        assert_eq!(ergonomics.penalty_points, 10);
        assert_eq!(ergonomics.finding_count, 1);
    }

    #[test]
    fn total_score_saturates_at_zero() {
        let findings = vec![finding("a", ScoreBucket::Security, 200)];
        let breakdown = ScoreBreakdown::from_findings(&findings, 100);
        assert_eq!(breakdown.total_score, 0);
    }

    #[test]
    fn scan_runs_registry_against_server() {
        let mut server = NormalizedServer::new("test");
        server.tools.push(NormalizedTool {
            name: "helper".to_string(),
            description: None,
            input_schema: serde_json::json!({}),
            metadata: BTreeMap::new(),
        });
        let report = scan(server, 100);
        assert!(report
            .findings
            .iter()
            .any(|f| f.rule_id == "overly_generic_tool_name"));
        assert!(report
            .findings
            .iter()
            .any(|f| f.rule_id == "missing_tool_description"));
        assert!(report.total_score() < 100);
    }
}
