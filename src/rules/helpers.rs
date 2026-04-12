//! Shared helpers used by multiple rules.
//!
//! Rules in this crate share a small set of primitives for reading a
//! [`NormalizedTool`]: normalised lowercase text, alphanumeric tokenisers,
//! tiny schema accessors, and evidence-string formatters. The helpers are
//! deliberately dependency-free — no `regex` crate, no heavy parsers — so
//! a reader can follow any rule from top to bottom in one sitting.
//!
//! Key invariants these helpers MUST preserve, because reporters rely on
//! them to produce stable output:
//!
//! * [`normalize_text`] strips whitespace and lowercases ASCII.
//! * [`matching_markers`] / [`matching_keys`] preserve the **marker**
//!   declaration order (not the haystack order) — this keeps evidence
//!   strings deterministic.
//! * [`single_quoted_repr`] / [`single_quoted_list_repr`] emit
//!   single-quoted strings safe for ASCII identifiers. They panic-free but
//!   are not a general-purpose escape routine; do not pass arbitrary user
//!   data through them.

use crate::models::NormalizedTool;
use serde_json::Value;

// ---------- keyword lists shared by multiple rules ------------------------

pub const GENERIC_INPUT_KEYS: &[&str] = &[
    "input",
    "payload",
    "data",
    "body",
    "request",
    "params",
    "parameters",
    "options",
    "query",
    "filter",
    "command",
];

pub const CRITICAL_KEYS: &[&str] = &[
    "path",
    "url",
    "uri",
    "endpoint",
    "host",
    "port",
    "command",
    "source",
    "destination",
    "content",
    "body",
];

pub const PATH_KEYS: &[&str] = &[
    "path",
    "file_path",
    "filepath",
    "filename",
    "target_path",
    "directory",
];

pub const CONTENT_KEYS: &[&str] = &["content", "text", "body", "data", "contents"];

pub const URL_KEYS: &[&str] = &["url", "uri", "endpoint", "host", "webhook_url"];

pub const SCOPE_HINTS: &[&str] = &[
    "allowed directories",
    "allowed directory",
    "within allowed",
    "working directory",
    "workspace",
    "sandbox",
    "project directory",
    "scoped",
];

pub const INPUTFUL_TOOL_MARKERS: &[&str] = &[
    "input", "payload", "data", "body", "request", "query", "search", "debug", "submit", "send",
];

// ---------- text helpers ---------------------------------------------------

/// Return `value.strip().lower()` — is ASCII-only
/// for ASCII input, which is all any rule uses it for.
pub fn normalize_text(value: Option<&str>) -> String {
    match value {
        None => String::new(),
        Some(v) => v.trim().to_ascii_lowercase(),
    }
}

/// Lowercase tool name + description concatenated with a single space.
pub fn tool_text_lower(tool: &NormalizedTool) -> String {
    let mut s = String::with_capacity(
        tool.name.len() + tool.description.as_ref().map(|d| d.len() + 1).unwrap_or(0),
    );
    s.push_str(&tool.name.to_ascii_lowercase());
    if let Some(desc) = &tool.description {
        s.push(' ');
        s.push_str(&desc.to_ascii_lowercase());
    }
    s
}

/// Return every needle in `markers` found in `haystack`, preserving the
/// declaration order of `markers`.
pub fn matching_markers<'a>(haystack: &str, markers: &'a [&'a str]) -> Vec<&'a str> {
    markers
        .iter()
        .copied()
        .filter(|m| haystack.contains(m))
        .collect()
}

/// Return every key in `keys` that appears in `property_names`, preserving
/// the declaration order of `keys`.
pub fn matching_keys<'a>(property_names: &[String], keys: &'a [&'a str]) -> Vec<&'a str> {
    keys.iter()
        .copied()
        .filter(|k| property_names.iter().any(|n| n == k))
        .collect()
}

/// Split a lowercased string into `[a-z0-9]+` tokens. Used by rules that
/// want whole-word matching without pulling in a regex dependency.
pub fn alnum_tokens(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    for ch in text.chars() {
        if ch.is_ascii_lowercase() || ch.is_ascii_digit() {
            current.push(ch);
        } else if !current.is_empty() {
            out.push(std::mem::take(&mut current));
        }
    }
    if !current.is_empty() {
        out.push(current);
    }
    out
}

// ---------- schema helpers -------------------------------------------------

/// Return the top-level `type` string when present.
pub fn schema_type(schema: &Value) -> Option<&str> {
    schema.get("type").and_then(Value::as_str)
}

/// Return the keys of the top-level `properties` object (lowercased) in
/// declaration order. Empty when the schema has no object-typed properties.
pub fn schema_property_names(schema: &Value) -> Vec<String> {
    schema
        .get("properties")
        .and_then(Value::as_object)
        .map(|obj| obj.keys().map(|k| k.to_ascii_lowercase()).collect())
        .unwrap_or_default()
}

/// Return the `properties` object directly (so rules can peek at subschemas).
pub fn schema_properties(schema: &Value) -> Option<&serde_json::Map<String, Value>> {
    schema.get("properties").and_then(Value::as_object)
}

/// Return lowercased `required` field names, skipping empty / non-string
/// entries. Canonical normalization.
pub fn schema_required_fields(schema: &Value) -> Vec<String> {
    let Some(arr) = schema.get("required").and_then(Value::as_array) else {
        return Vec::new();
    };
    arr.iter()
        .filter_map(|v| v.as_str())
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Return the raw `additionalProperties` value when present.
pub fn additional_properties(schema: &Value) -> Option<&Value> {
    schema.get("additionalProperties")
}

/// Return whether the tool description or input schema hints at scoped
/// side-effects (e.g. "within allowed directories").
pub fn has_scope_hint(description: Option<&str>, schema: &Value) -> bool {
    let normalized_description = normalize_text(description);
    if SCOPE_HINTS
        .iter()
        .any(|m| normalized_description.contains(m))
    {
        return true;
    }

    let Some(properties) = schema_properties(schema) else {
        return false;
    };

    for (property_name, property_schema) in properties {
        let name_lower = property_name.to_ascii_lowercase();
        if matches!(
            name_lower.as_str(),
            "root" | "workspace" | "allowed_directory" | "scope"
        ) {
            return true;
        }
        if let Some(obj) = property_schema.as_object() {
            let desc = obj.get("description").and_then(Value::as_str);
            let desc_norm = normalize_text(desc);
            if SCOPE_HINTS.iter().any(|m| desc_norm.contains(m)) {
                return true;
            }
        }
    }

    false
}

/// Return whether the tool name or description contains any inputful
/// marker (input, payload, send, submit, ...).
pub fn looks_like_inputful_tool(name: &str, description: Option<&str>) -> bool {
    let name_lower = name.trim().to_ascii_lowercase();
    let desc_lower = normalize_text(description);
    INPUTFUL_TOOL_MARKERS
        .iter()
        .any(|m| name_lower.contains(m) || desc_lower.contains(m))
}

// ---------- Single-quoted repr helpers -------------------------------------

/// Approximate `repr()`-style single-quoted for a string. Good enough for ASCII
/// identifiers (tool names, marker tokens), which is every caller we have.
pub fn single_quoted_repr(s: &str) -> String {
    let has_single = s.contains('\'');
    let has_double = s.contains('"');
    let quote = if has_single && !has_double { '"' } else { '\'' };
    let mut out = String::with_capacity(s.len() + 2);
    out.push(quote);
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\x{:02x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push(quote);
    out
}

/// Approximate `repr(list_of_strings)`-style — emits
/// `['a', 'b', 'c']` with single-quoted items.
pub fn single_quoted_list_repr(items: &[&str]) -> String {
    let mut out = String::from("[");
    for (i, item) in items.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        out.push_str(&single_quoted_repr(item));
    }
    out.push(']');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn tool(name: &str, description: Option<&str>) -> NormalizedTool {
        NormalizedTool {
            name: name.to_string(),
            description: description.map(|d| d.to_string()),
            input_schema: serde_json::json!({}),
            metadata: BTreeMap::new(),
        }
    }

    #[test]
    fn normalize_text_strips_and_lowercases() {
        assert_eq!(normalize_text(Some("  Hello WORLD  ")), "hello world");
        assert_eq!(normalize_text(None), "");
        assert_eq!(normalize_text(Some("")), "");
    }

    #[test]
    fn tool_text_lower_joins_name_and_description() {
        let t = tool("MyTool", Some("Runs SHELL commands"));
        assert_eq!(tool_text_lower(&t), "mytool runs shell commands");
    }

    #[test]
    fn matching_markers_preserves_marker_order() {
        let haystack = "runs exec shell commands";
        let markers = ["shell", "exec", "rm"];
        assert_eq!(matching_markers(haystack, &markers), vec!["shell", "exec"]);
    }

    #[test]
    fn matching_keys_preserves_key_order() {
        let property_names = vec!["path".to_string(), "url".to_string()];
        let keys = ["url", "path", "port"];
        assert_eq!(matching_keys(&property_names, &keys), vec!["url", "path"]);
    }

    #[test]
    fn alnum_tokens_extracts_lowercase_tokens() {
        assert_eq!(
            alnum_tokens("delete-all files"),
            vec!["delete", "all", "files"]
        );
        assert_eq!(alnum_tokens("123 abc"), vec!["123", "abc"]);
        assert_eq!(alnum_tokens(""), Vec::<String>::new());
    }

    #[test]
    fn schema_property_names_returns_lowercased_keys() {
        let schema = serde_json::json!({"properties": {"URL": {}, "Path": {}}});
        let names = schema_property_names(&schema);
        assert!(names.contains(&"url".to_string()));
        assert!(names.contains(&"path".to_string()));
    }

    #[test]
    fn schema_required_fields_filters_and_lowercases() {
        let schema = serde_json::json!({"required": ["  URL  ", "", 42, "path"]});
        let required = schema_required_fields(&schema);
        assert_eq!(required, vec!["url".to_string(), "path".to_string()]);
    }

    #[test]
    fn additional_properties_returns_value() {
        let schema = serde_json::json!({"additionalProperties": true});
        assert_eq!(additional_properties(&schema), Some(&Value::Bool(true)));
    }

    #[test]
    fn has_scope_hint_matches_description_or_schema() {
        let schema = serde_json::json!({});
        assert!(has_scope_hint(
            Some("writes only within allowed directories"),
            &schema
        ));
        let scoped_schema = serde_json::json!({
            "properties": {"workspace": {"type": "string"}}
        });
        assert!(has_scope_hint(None, &scoped_schema));
        let scoped_via_prop = serde_json::json!({
            "properties": {
                "root": {"type": "string", "description": "project directory path"}
            }
        });
        assert!(has_scope_hint(None, &scoped_via_prop));
        let unscoped = serde_json::json!({"properties": {"path": {}}});
        assert!(!has_scope_hint(None, &unscoped));
    }

    #[test]
    fn looks_like_inputful_tool_matches_name_or_description() {
        assert!(looks_like_inputful_tool("submit_form", None));
        assert!(looks_like_inputful_tool("any", Some("send a payload")));
        assert!(!looks_like_inputful_tool("abc", Some("static")));
    }

    #[test]
    fn single_quoted_repr_matches_common_cases() {
        assert_eq!(single_quoted_repr("abc"), "'abc'");
        assert_eq!(single_quoted_repr(""), "''");
        assert_eq!(single_quoted_repr("it's"), "\"it's\"");
        assert_eq!(single_quoted_repr("with \"quotes\""), "'with \"quotes\"'");
        assert_eq!(single_quoted_repr("tab\there"), "'tab\\there'");
    }

    #[test]
    fn single_quoted_list_repr_matches_markers() {
        assert_eq!(
            single_quoted_list_repr(&["shell", "exec"]),
            "['shell', 'exec']"
        );
        assert_eq!(single_quoted_list_repr(&[]), "[]");
        assert_eq!(single_quoted_list_repr(&["one"]), "['one']");
    }
}
