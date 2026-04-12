//! Schema rules — checks that live on the tool's `inputSchema`.
//!
//! A strong input schema is the best guardrail an MCP server has: it tells
//! the agent exactly what can be passed, and it gives deterministic
//! parameter validation on the server side. The four rules in this file
//! catch the most common weakening patterns: no top-level type, catch-all
//! `additionalProperties: true`, generic `payload` objects with no inner
//! type, and critical fields (like `path` or `command`) left optional.

use std::collections::BTreeMap;

use serde_json::Value;

use crate::models::{
    Finding, FindingCategory, NormalizedServer, NormalizedTool, RiskCategory, ScoreBucket, Severity,
};
use crate::rules::helpers::{
    additional_properties, looks_like_inputful_tool, matching_keys, schema_properties,
    schema_property_names, schema_required_fields, schema_type, single_quoted_list_repr,
    single_quoted_repr, GENERIC_INPUT_KEYS,
};
use crate::rules::Rule;

// --- missing_schema_type --------------------------------------------------

/// Rule: `missing_schema_type`. Fires when the top-level `type` is absent.
pub struct MissingType;

impl Rule for MissingType {
    fn id(&self) -> &'static str {
        "missing_schema_type"
    }
    fn title(&self) -> &'static str {
        "Missing schema type"
    }
    fn rationale(&self) -> &'static str {
        "Tool input schemas should declare a top-level type."
    }
    fn severity(&self) -> Severity {
        Severity::Warning
    }
    fn category(&self) -> FindingCategory {
        FindingCategory::InputSchema
    }
    fn risk_category(&self) -> RiskCategory {
        RiskCategory::SchemaHygiene
    }
    fn bucket(&self) -> ScoreBucket {
        ScoreBucket::Conformance
    }
    fn tags(&self) -> &'static [&'static str] {
        &["schema", "validation"]
    }

    fn evaluate(&self, server: &NormalizedServer) -> Vec<Finding> {
        let mut findings = Vec::new();
        for tool in &server.tools {
            if schema_type(&tool.input_schema).is_some() {
                continue;
            }
            // An empty schema is only flagged when the tool's name or
            // description implies it accepts free-form input — otherwise
            // no-arg tools would trigger this rule spuriously.
            let is_empty = tool
                .input_schema
                .as_object()
                .map(|o| o.is_empty())
                .unwrap_or(true);
            if is_empty && !looks_like_inputful_tool(&tool.name, tool.description.as_deref()) {
                continue;
            }
            let message = format!(
                "Tool {} omits the top-level input schema type.",
                single_quoted_repr(&tool.name)
            );
            findings.push(self.make_finding(
                message,
                vec!["schema_type=<missing>".to_string()],
                Some(tool.name.clone()),
                BTreeMap::new(),
            ));
        }
        findings
    }
}

// --- schema_allows_arbitrary_properties ----------------------------------

/// Rule: `schema_allows_arbitrary_properties`. Fires when an object schema
/// explicitly sets `additionalProperties: true`.
pub struct ArbitraryProperties;

impl Rule for ArbitraryProperties {
    fn id(&self) -> &'static str {
        "schema_allows_arbitrary_properties"
    }
    fn title(&self) -> &'static str {
        "Schema allows arbitrary properties"
    }
    fn rationale(&self) -> &'static str {
        "Tool input schemas should not allow arbitrary top-level properties."
    }
    fn severity(&self) -> Severity {
        Severity::Warning
    }
    fn category(&self) -> FindingCategory {
        FindingCategory::InputSchema
    }
    fn risk_category(&self) -> RiskCategory {
        RiskCategory::SchemaHygiene
    }
    fn bucket(&self) -> ScoreBucket {
        ScoreBucket::Conformance
    }
    fn tags(&self) -> &'static [&'static str] {
        &["schema", "validation"]
    }

    fn evaluate(&self, server: &NormalizedServer) -> Vec<Finding> {
        let mut findings = Vec::new();
        for tool in &server.tools {
            if schema_type(&tool.input_schema) != Some("object") {
                continue;
            }
            if additional_properties(&tool.input_schema) != Some(&Value::Bool(true)) {
                continue;
            }
            let property_count = schema_properties(&tool.input_schema)
                .map(|o| o.len())
                .unwrap_or(0);
            let message = format!(
                "Tool {} allows arbitrary additional input properties.",
                single_quoted_repr(&tool.name)
            );
            findings.push(self.make_finding(
                message,
                vec![
                    "additionalProperties=True".to_string(),
                    format!("property_count={property_count}"),
                ],
                Some(tool.name.clone()),
                BTreeMap::new(),
            ));
        }
        findings
    }
}

// --- weak_input_schema ----------------------------------------------------

/// Rule: `weak_input_schema`. Fires on two patterns:
///
/// 1. An "inputful" tool (name/description suggests free-form input) with
///    an empty object schema.
/// 2. An object schema that has a generic catch-all property (`payload`,
///    `data`, ...) whose own type is missing or is an unconstrained object.
pub struct WeakInput;

impl Rule for WeakInput {
    fn id(&self) -> &'static str {
        "weak_input_schema"
    }
    fn title(&self) -> &'static str {
        "Weak input schema"
    }
    fn rationale(&self) -> &'static str {
        "Tool input schemas should constrain free-form payloads clearly."
    }
    fn severity(&self) -> Severity {
        Severity::Warning
    }
    fn category(&self) -> FindingCategory {
        FindingCategory::InputSchema
    }
    fn risk_category(&self) -> RiskCategory {
        RiskCategory::SchemaHygiene
    }
    fn bucket(&self) -> ScoreBucket {
        ScoreBucket::Ergonomics
    }
    fn tags(&self) -> &'static [&'static str] {
        &["schema", "validation"]
    }

    fn evaluate(&self, server: &NormalizedServer) -> Vec<Finding> {
        let mut findings = Vec::new();
        for tool in &server.tools {
            let reasons = weak_input_reasons(tool);
            if reasons.is_empty() {
                continue;
            }
            let message = format!(
                "Tool {} exposes a weak input schema that leaves free-form input underconstrained.",
                single_quoted_repr(&tool.name)
            );
            findings.push(self.make_finding(
                message,
                reasons,
                Some(tool.name.clone()),
                BTreeMap::new(),
            ));
        }
        findings
    }
}

fn weak_input_reasons(tool: &NormalizedTool) -> Vec<String> {
    if schema_type(&tool.input_schema) != Some("object") {
        return Vec::new();
    }

    let Some(properties) = schema_properties(&tool.input_schema) else {
        if looks_like_inputful_tool(&tool.name, tool.description.as_deref()) {
            return vec!["matched_heuristic=inputful_tool_with_empty_object_schema".to_string()];
        }
        return Vec::new();
    };

    if properties.is_empty() {
        if looks_like_inputful_tool(&tool.name, tool.description.as_deref()) {
            return vec!["matched_heuristic=inputful_tool_with_empty_object_schema".to_string()];
        }
        return Vec::new();
    }

    // `matching_keys` is case-sensitive, mirroring the contract — we do
    // not lowercase properties here so the evidence strings stay stable.
    let property_names: Vec<String> = properties.keys().cloned().collect();
    let generic_input_keys = matching_keys(&property_names, GENERIC_INPUT_KEYS);

    let mut weak_generic_keys: Vec<&str> = Vec::new();
    for key in &generic_input_keys {
        let Some(subschema) = properties.get(*key).and_then(|v| v.as_object()) else {
            weak_generic_keys.push(key);
            continue;
        };
        let property_type = subschema.get("type").and_then(|v| v.as_str());
        let property_properties = subschema.get("properties");
        let property_additional_properties = subschema.get("additionalProperties");
        let Some(ptype) = property_type else {
            weak_generic_keys.push(key);
            continue;
        };
        if ptype == "object"
            && !property_properties.map(|v| v.is_object()).unwrap_or(false)
            && property_additional_properties != Some(&Value::Bool(false))
        {
            weak_generic_keys.push(key);
        }
    }

    if weak_generic_keys.is_empty() {
        return Vec::new();
    }
    vec![format!(
        "generic_input_keys={}",
        single_quoted_list_repr(&weak_generic_keys)
    )]
}

// --- missing_required_for_critical_fields --------------------------------

/// Rule: `missing_required_for_critical_fields`. Fires when a critical
/// field (`command`, `path`, `url`, ...) is declared but left optional in
/// the `required` array.
pub struct MissingRequiredCritical;

const CRITICAL_REQUIRED_KEYS: &[&str] = &[
    "command",
    "path",
    "file_path",
    "filepath",
    "url",
    "uri",
    "endpoint",
];

impl Rule for MissingRequiredCritical {
    fn id(&self) -> &'static str {
        "missing_required_for_critical_fields"
    }
    fn title(&self) -> &'static str {
        "Missing required critical fields"
    }
    fn rationale(&self) -> &'static str {
        "Critical schema fields such as path, command, or URL should be required."
    }
    fn severity(&self) -> Severity {
        Severity::Warning
    }
    fn category(&self) -> FindingCategory {
        FindingCategory::InputSchema
    }
    fn risk_category(&self) -> RiskCategory {
        RiskCategory::SchemaHygiene
    }
    fn bucket(&self) -> ScoreBucket {
        ScoreBucket::Conformance
    }
    fn tags(&self) -> &'static [&'static str] {
        &["schema", "validation"]
    }

    fn evaluate(&self, server: &NormalizedServer) -> Vec<Finding> {
        let mut findings = Vec::new();
        for tool in &server.tools {
            if schema_type(&tool.input_schema) != Some("object") {
                continue;
            }
            let property_names = schema_property_names(&tool.input_schema);
            let required_fields = schema_required_fields(&tool.input_schema);

            let optional_critical_fields: Vec<&str> = CRITICAL_REQUIRED_KEYS
                .iter()
                .copied()
                .filter(|k| {
                    property_names.iter().any(|n| n == k) && !required_fields.iter().any(|r| r == k)
                })
                .collect();
            if optional_critical_fields.is_empty() {
                continue;
            }

            let required_refs: Vec<&str> = required_fields.iter().map(|s| s.as_str()).collect();
            let evidence = vec![
                format!(
                    "critical_fields={}",
                    single_quoted_list_repr(&optional_critical_fields)
                ),
                format!(
                    "required_fields={}",
                    single_quoted_list_repr(&required_refs)
                ),
            ];
            let message = format!(
                "Tool {} defines critical input fields that are not required.",
                single_quoted_repr(&tool.name)
            );
            findings.push(self.make_finding(
                message,
                evidence,
                Some(tool.name.clone()),
                BTreeMap::new(),
            ));
        }
        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::NormalizedTool;

    fn with_schema(name: &str, description: Option<&str>, schema: Value) -> NormalizedTool {
        NormalizedTool {
            name: name.to_string(),
            description: description.map(String::from),
            input_schema: schema,
            metadata: BTreeMap::new(),
        }
    }

    // MissingType

    #[test]
    fn missing_type_fires_on_inputful_tool_with_empty_schema() {
        let mut server = NormalizedServer::new("test");
        server.tools.push(with_schema(
            "send_message",
            Some("sends a message"),
            serde_json::json!({}),
        ));
        assert_eq!(MissingType.evaluate(&server).len(), 1);
    }

    #[test]
    fn missing_type_skips_no_arg_tool() {
        let mut server = NormalizedServer::new("test");
        server.tools.push(with_schema(
            "ping",
            Some("returns pong"),
            serde_json::json!({}),
        ));
        assert!(MissingType.evaluate(&server).is_empty());
    }

    #[test]
    fn missing_type_skips_schema_with_type() {
        let mut server = NormalizedServer::new("test");
        server.tools.push(with_schema(
            "ping",
            None,
            serde_json::json!({"type": "object"}),
        ));
        assert!(MissingType.evaluate(&server).is_empty());
    }

    // ArbitraryProperties

    #[test]
    fn arbitrary_properties_fires_when_true() {
        let mut server = NormalizedServer::new("test");
        server.tools.push(with_schema(
            "open",
            None,
            serde_json::json!({"type": "object", "additionalProperties": true}),
        ));
        assert_eq!(ArbitraryProperties.evaluate(&server).len(), 1);
    }

    #[test]
    fn arbitrary_properties_skips_false() {
        let mut server = NormalizedServer::new("test");
        server.tools.push(with_schema(
            "closed",
            None,
            serde_json::json!({"type": "object", "additionalProperties": false}),
        ));
        assert!(ArbitraryProperties.evaluate(&server).is_empty());
    }

    // WeakInput

    #[test]
    fn weak_input_fires_on_empty_object_for_inputful_tool() {
        let mut server = NormalizedServer::new("test");
        server.tools.push(with_schema(
            "submit_input",
            Some("sends input"),
            serde_json::json!({"type": "object"}),
        ));
        assert_eq!(WeakInput.evaluate(&server).len(), 1);
    }

    #[test]
    fn weak_input_fires_on_generic_field_without_type() {
        let mut server = NormalizedServer::new("test");
        server.tools.push(with_schema(
            "submit_input",
            Some("sends input"),
            serde_json::json!({
                "type": "object",
                "properties": {"payload": {}}
            }),
        ));
        let findings = WeakInput.evaluate(&server);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].evidence[0].contains("'payload'"));
    }

    #[test]
    fn weak_input_skips_constrained_schema() {
        let mut server = NormalizedServer::new("test");
        server.tools.push(with_schema(
            "submit_input",
            Some("sends input"),
            serde_json::json!({
                "type": "object",
                "properties": {"payload": {"type": "string"}}
            }),
        ));
        assert!(WeakInput.evaluate(&server).is_empty());
    }

    // MissingRequiredCritical

    #[test]
    fn missing_required_fires_on_optional_path() {
        let mut server = NormalizedServer::new("test");
        server.tools.push(with_schema(
            "open",
            None,
            serde_json::json!({
                "type": "object",
                "properties": {"path": {}, "mode": {}},
                "required": ["mode"]
            }),
        ));
        let findings = MissingRequiredCritical.evaluate(&server);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].evidence[0].contains("'path'"));
    }

    #[test]
    fn missing_required_skips_when_all_critical_required() {
        let mut server = NormalizedServer::new("test");
        server.tools.push(with_schema(
            "open",
            None,
            serde_json::json!({
                "type": "object",
                "properties": {"path": {}},
                "required": ["path"]
            }),
        ));
        assert!(MissingRequiredCritical.evaluate(&server).is_empty());
    }
}
