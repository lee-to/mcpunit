//! Core domain types shared by every layer of mcpunit.
//!
//! The enums in this file are the single source of truth for severity,
//! finding taxonomy, risk taxonomy, and score buckets. Adding a variant to
//! any of them intentionally breaks compilation in every reporter and rule
//! — that's the whole reason for keeping these types closed.
//!
//! On-wire casing is stable: lowercase `"info"`, kebab-case
//! `"tool-identity"`, snake_case `"file_system"`, and so on. Each variant
//! carries its own `#[serde(rename)]` so changing a Rust identifier never
//! accidentally changes the JSON / SARIF shape.
//!
//! **Do not reorder variants.** Declaration order is the on-wire iteration
//! order for `category_scores` in the JSON reporter, and every downstream
//! consumer of the audit report relies on that ordering.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Severity of a single finding.
///
/// Numeric score impact: `INFO=0`, `WARNING=10`, `ERROR=20`. Changing
/// these values reshapes every audit in the field, so they are a hard
/// invariant — callers downstream (dashboards, gates, historical charts)
/// depend on them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    #[serde(rename = "info")]
    Info,
    #[serde(rename = "warning")]
    Warning,
    #[serde(rename = "error")]
    Error,
}

impl Severity {
    /// Stable lowercase wire string (`info` / `warning` / `error`).
    pub const fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Warning => "warning",
            Severity::Error => "error",
        }
    }
}

impl Severity {
    /// Score penalty associated with this severity level.
    pub const fn score_impact(self) -> u32 {
        match self {
            Severity::Info => 0,
            Severity::Warning => 10,
            Severity::Error => 20,
        }
    }

    /// SARIF-level string (`note` / `warning` / `error`) used by the SARIF
    /// reporter's `defaultConfiguration.level` and `results[].level`.
    pub const fn sarif_level(self) -> &'static str {
        match self {
            Severity::Info => "note",
            Severity::Warning => "warning",
            Severity::Error => "error",
        }
    }
}

/// Orthogonal classification of what aspect of a tool a finding targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum FindingCategory {
    #[serde(rename = "tool-identity")]
    ToolIdentity,
    #[serde(rename = "tool-description")]
    ToolDescription,
    #[serde(rename = "input-schema")]
    InputSchema,
    #[serde(rename = "capability")]
    Capability,
    // New variants MUST be appended — declaration order is the on-wire
    // iteration order for `category_scores`, so inserting in the middle
    // would break every downstream dashboard.
    #[serde(rename = "prompt-identity")]
    PromptIdentity,
    #[serde(rename = "prompt-description")]
    PromptDescription,
}

impl FindingCategory {
    pub const fn as_str(self) -> &'static str {
        match self {
            FindingCategory::ToolIdentity => "tool-identity",
            FindingCategory::ToolDescription => "tool-description",
            FindingCategory::InputSchema => "input-schema",
            FindingCategory::Capability => "capability",
            FindingCategory::PromptIdentity => "prompt-identity",
            FindingCategory::PromptDescription => "prompt-description",
        }
    }
}

/// Risk surface a finding exposes. Used to group findings in the SARIF
/// `properties` bag and in terminal output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RiskCategory {
    #[serde(rename = "file_system")]
    FileSystem,
    #[serde(rename = "command_execution")]
    CommandExecution,
    #[serde(rename = "network")]
    Network,
    #[serde(rename = "external_side_effects")]
    ExternalSideEffects,
    #[serde(rename = "schema_hygiene")]
    SchemaHygiene,
    #[serde(rename = "metadata_hygiene")]
    MetadataHygiene,
}

impl RiskCategory {
    pub const fn as_str(self) -> &'static str {
        match self {
            RiskCategory::FileSystem => "file_system",
            RiskCategory::CommandExecution => "command_execution",
            RiskCategory::Network => "network",
            RiskCategory::ExternalSideEffects => "external_side_effects",
            RiskCategory::SchemaHygiene => "schema_hygiene",
            RiskCategory::MetadataHygiene => "metadata_hygiene",
        }
    }

    /// Human-readable label used by the terminal / markdown reporters.
    pub const fn label(self) -> &'static str {
        match self {
            RiskCategory::FileSystem => "file system",
            RiskCategory::CommandExecution => "command execution",
            RiskCategory::Network => "network",
            RiskCategory::ExternalSideEffects => "external side effects",
            RiskCategory::SchemaHygiene => "schema hygiene",
            RiskCategory::MetadataHygiene => "metadata hygiene",
        }
    }

    pub const ALL: &'static [RiskCategory] = &[
        RiskCategory::FileSystem,
        RiskCategory::CommandExecution,
        RiskCategory::Network,
        RiskCategory::ExternalSideEffects,
        RiskCategory::SchemaHygiene,
        RiskCategory::MetadataHygiene,
    ];
}

/// Audit bucket used for per-category aggregation in the JSON reporter.
///
/// **Declaration order is on-wire order.** The JSON reporter walks this enum
/// in the order variants appear here to produce `audit.category_scores`.
/// Do not sort alphabetically when serialising.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ScoreBucket {
    #[serde(rename = "conformance")]
    Conformance,
    #[serde(rename = "security")]
    Security,
    #[serde(rename = "ergonomics")]
    Ergonomics,
    #[serde(rename = "metadata")]
    Metadata,
}

impl ScoreBucket {
    /// All buckets in declaration (on-wire) order.
    pub const ALL: &'static [ScoreBucket] = &[
        ScoreBucket::Conformance,
        ScoreBucket::Security,
        ScoreBucket::Ergonomics,
        ScoreBucket::Metadata,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            ScoreBucket::Conformance => "conformance",
            ScoreBucket::Security => "security",
            ScoreBucket::Ergonomics => "ergonomics",
            ScoreBucket::Metadata => "metadata",
        }
    }

    pub const fn label(self) -> &'static str {
        self.as_str()
    }
}

/// Free-form metadata bag attached to servers, tools, and findings.
pub type MetadataMap = BTreeMap<String, serde_json::Value>;

/// Snapshot of an MCP server after `initialize` + `tools/list` have returned.
///
/// The `response_sizes` map records the byte length observed on the wire for
/// each JSON-RPC method call; rules that care about payload size (notably
/// [`response_too_large`]) read from it. Transports populate this map as they
/// read responses.
///
/// [`response_too_large`]: crate::rules::response_too_large
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NormalizedServer {
    pub target: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,

    pub tools: Vec<NormalizedTool>,

    /// Prompts discovered via `prompts/list`. Empty when the server did
    /// not advertise `capabilities.prompts`, was normalised from a
    /// tools-only fixture, or the transport could not enumerate prompts.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub prompts: Vec<NormalizedPrompt>,

    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: MetadataMap,

    /// `method` → `response byte length`. Populated by transports during
    /// discovery. Empty when the server was normalised from a static fixture.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub response_sizes: BTreeMap<String, u64>,
}

impl NormalizedServer {
    pub fn new(target: impl Into<String>) -> Self {
        Self {
            target: target.into(),
            name: None,
            version: None,
            tools: Vec::new(),
            prompts: Vec::new(),
            metadata: BTreeMap::new(),
            response_sizes: BTreeMap::new(),
        }
    }
}

/// A single tool as advertised by the MCP server's `tools/list` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NormalizedTool {
    pub name: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    #[serde(default = "default_input_schema")]
    pub input_schema: serde_json::Value,

    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: MetadataMap,
}

fn default_input_schema() -> serde_json::Value {
    serde_json::Value::Object(serde_json::Map::new())
}

/// A single prompt as advertised by the MCP server's `prompts/list`
/// response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NormalizedPrompt {
    pub name: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub arguments: Vec<NormalizedPromptArgument>,

    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: MetadataMap,
}

/// A single argument of a prompt, as declared in its `arguments` list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NormalizedPromptArgument {
    pub name: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub required: Option<bool>,
}

/// A single rule violation attached to a server scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub rule_id: String,
    pub level: Severity,
    pub message: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,

    pub category: FindingCategory,
    pub risk_category: RiskCategory,
    pub bucket: ScoreBucket,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<String>,

    pub penalty: u32,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_name: Option<String>,

    /// Name of the prompt this finding is about, when the rule targets a
    /// prompt rather than a tool. Mutually exclusive with `tool_name` in
    /// practice — rules set exactly one of the two.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prompt_name: Option<String>,

    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: MetadataMap,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_serialises_as_lowercase() {
        assert_eq!(serde_json::to_string(&Severity::Info).unwrap(), "\"info\"");
        assert_eq!(
            serde_json::to_string(&Severity::Warning).unwrap(),
            "\"warning\""
        );
        assert_eq!(
            serde_json::to_string(&Severity::Error).unwrap(),
            "\"error\""
        );
    }

    #[test]
    fn severity_score_impact_matches_contract() {
        assert_eq!(Severity::Info.score_impact(), 0);
        assert_eq!(Severity::Warning.score_impact(), 10);
        assert_eq!(Severity::Error.score_impact(), 20);
    }

    #[test]
    fn finding_category_serialises_as_kebab() {
        assert_eq!(
            serde_json::to_string(&FindingCategory::ToolIdentity).unwrap(),
            "\"tool-identity\""
        );
        assert_eq!(
            serde_json::to_string(&FindingCategory::InputSchema).unwrap(),
            "\"input-schema\""
        );
    }

    #[test]
    fn risk_category_serialises_as_snake() {
        assert_eq!(
            serde_json::to_string(&RiskCategory::FileSystem).unwrap(),
            "\"file_system\""
        );
        assert_eq!(
            serde_json::to_string(&RiskCategory::CommandExecution).unwrap(),
            "\"command_execution\""
        );
        assert_eq!(
            serde_json::to_string(&RiskCategory::ExternalSideEffects).unwrap(),
            "\"external_side_effects\""
        );
    }

    #[test]
    fn score_bucket_serialises_lowercase() {
        assert_eq!(
            serde_json::to_string(&ScoreBucket::Conformance).unwrap(),
            "\"conformance\""
        );
    }

    #[test]
    fn score_bucket_all_is_in_declaration_order() {
        assert_eq!(
            ScoreBucket::ALL,
            &[
                ScoreBucket::Conformance,
                ScoreBucket::Security,
                ScoreBucket::Ergonomics,
                ScoreBucket::Metadata,
            ]
        );
    }

    #[test]
    fn normalized_server_round_trips_through_json() {
        let mut server = NormalizedServer::new("stdio:fake");
        server.name = Some("fake".to_string());
        server.tools.push(NormalizedTool {
            name: "echo".to_string(),
            description: Some("echo text".to_string()),
            input_schema: serde_json::json!({"type": "object"}),
            metadata: BTreeMap::new(),
        });
        server.response_sizes.insert("tools/list".to_string(), 1234);

        let encoded = serde_json::to_string(&server).unwrap();
        let decoded: NormalizedServer = serde_json::from_str(&encoded).unwrap();

        assert_eq!(decoded.target, "stdio:fake");
        assert_eq!(decoded.tools.len(), 1);
        assert_eq!(decoded.response_sizes.get("tools/list"), Some(&1234));
    }
}
