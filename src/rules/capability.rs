//! Capability rules — checks that flag high-risk tool capabilities.
//!
//! Unlike identity / description / schema rules (all catalogue hygiene),
//! these rules attempt to infer what a tool actually *does* from its
//! advertised surface. The heuristics follow the same shape in every
//! rule:
//!
//! 1. Normalise the tool `name` and `description` to lowercase.
//! 2. Collect the tool's input schema property names.
//! 3. Match against a small set of marker lists — `name_markers`,
//!    `description_markers`, `input_keys` — and emit a finding only when
//!    the combination crosses a rule-specific threshold.
//!
//! All evidence strings are built via [`single_quoted_list_repr`] so the
//! on-wire format is stable. The rules are deliberately unsophisticated:
//! detection is based on substring matching rather than ML or pattern
//! engines, because false positives here are cheaper than opaque false
//! negatives — a maintainer can always override a rule.

use std::collections::{BTreeMap, HashSet};

use crate::models::{
    Finding, FindingCategory, NormalizedServer, RiskCategory, ScoreBucket, Severity,
};
use crate::rules::helpers::{
    alnum_tokens, has_scope_hint, matching_keys, matching_markers, normalize_text,
    schema_property_names, single_quoted_list_repr, single_quoted_repr, CONTENT_KEYS, PATH_KEYS,
    URL_KEYS,
};
use crate::rules::Rule;

// --- dangerous_exec_tool --------------------------------------------------

/// Rule: `dangerous_exec_tool`. Flags tools that look like shell command
/// execution primitives (`exec_command`, `bash_run`, etc.).
pub struct ExecTool;

const EXEC_NAME_MARKERS: &[&str] = &[
    "exec",
    "shell",
    "command",
    "cmd",
    "bash",
    "powershell",
    "terminal",
];
const EXEC_DESC_MARKERS: &[&str] = &[
    "execute",
    "shell command",
    "host machine",
    "arbitrary command",
];
const EXEC_INPUT_KEYS: &[&str] = &["command", "cmd", "script", "shell"];

impl Rule for ExecTool {
    fn id(&self) -> &'static str {
        "dangerous_exec_tool"
    }
    fn title(&self) -> &'static str {
        "Dangerous execution tool"
    }
    fn rationale(&self) -> &'static str {
        "Tools that execute host shell commands are high risk."
    }
    fn severity(&self) -> Severity {
        Severity::Error
    }
    fn category(&self) -> FindingCategory {
        FindingCategory::Capability
    }
    fn risk_category(&self) -> RiskCategory {
        RiskCategory::CommandExecution
    }
    fn bucket(&self) -> ScoreBucket {
        ScoreBucket::Security
    }
    fn tags(&self) -> &'static [&'static str] {
        &["capability", "execution"]
    }

    fn evaluate(&self, server: &NormalizedServer) -> Vec<Finding> {
        let mut findings = Vec::new();
        for tool in &server.tools {
            let name = normalize_text(Some(&tool.name));
            let description = normalize_text(tool.description.as_deref());
            let property_names = schema_property_names(&tool.input_schema);

            let matched_name = matching_markers(&name, EXEC_NAME_MARKERS);
            let matched_desc = matching_markers(&description, EXEC_DESC_MARKERS);
            let matched_keys = matching_keys(&property_names, EXEC_INPUT_KEYS);

            if matched_name.is_empty() {
                continue;
            }
            if matched_desc.is_empty() && matched_keys.is_empty() {
                continue;
            }

            let mut evidence = vec![format!(
                "name_markers={}",
                single_quoted_list_repr(&matched_name)
            )];
            if !matched_desc.is_empty() {
                evidence.push(format!(
                    "description_markers={}",
                    single_quoted_list_repr(&matched_desc)
                ));
            }
            if !matched_keys.is_empty() {
                evidence.push(format!(
                    "input_keys={}",
                    single_quoted_list_repr(&matched_keys)
                ));
            }

            findings.push(self.make_finding(
                format!(
                    "Tool {} appears to expose host command execution.",
                    single_quoted_repr(&tool.name)
                ),
                evidence,
                Some(tool.name.clone()),
                BTreeMap::new(),
            ));
        }
        findings
    }
}

// --- dangerous_shell_download_exec ---------------------------------------

/// Rule: `dangerous_shell_download_exec`. The classic "curl | sh" pattern
/// — a tool that both fetches a remote resource and runs shell.
pub struct ShellDownloadExec;

const SDE_EXEC_MARKERS: &[&str] = &["exec", "shell", "command", "bash", "powershell"];
const SDE_DOWNLOAD_MARKERS: &[&str] = &[
    "download",
    "fetch",
    "curl",
    "wget",
    "remote script",
    "remote payload",
];
const SDE_EXEC_KEYS: &[&str] = &["command", "cmd", "script"];

impl Rule for ShellDownloadExec {
    fn id(&self) -> &'static str {
        "dangerous_shell_download_exec"
    }
    fn title(&self) -> &'static str {
        "Dangerous download-and-execute tool"
    }
    fn rationale(&self) -> &'static str {
        "Tools that combine remote download with shell execution are high risk."
    }
    fn severity(&self) -> Severity {
        Severity::Error
    }
    fn category(&self) -> FindingCategory {
        FindingCategory::Capability
    }
    fn risk_category(&self) -> RiskCategory {
        RiskCategory::CommandExecution
    }
    fn bucket(&self) -> ScoreBucket {
        ScoreBucket::Security
    }
    fn tags(&self) -> &'static [&'static str] {
        &["capability", "execution", "network"]
    }

    fn evaluate(&self, server: &NormalizedServer) -> Vec<Finding> {
        let mut findings = Vec::new();
        for tool in &server.tools {
            let name = normalize_text(Some(&tool.name));
            let description = normalize_text(tool.description.as_deref());
            let property_names = schema_property_names(&tool.input_schema);

            let matched_exec_markers: Vec<&str> = SDE_EXEC_MARKERS
                .iter()
                .copied()
                .filter(|m| name.contains(m))
                .collect();
            let matched_download_markers: Vec<&str> = SDE_DOWNLOAD_MARKERS
                .iter()
                .copied()
                .filter(|m| name.contains(m) || description.contains(m))
                .collect();
            let matched_exec_keys = matching_keys(&property_names, SDE_EXEC_KEYS);
            let matched_url_keys = matching_keys(&property_names, URL_KEYS);

            let has_exec = !matched_exec_markers.is_empty() || !matched_exec_keys.is_empty();
            let has_download = !matched_download_markers.is_empty() || !matched_url_keys.is_empty();
            if !(has_exec && has_download) {
                continue;
            }

            let mut evidence = Vec::new();
            if !matched_exec_markers.is_empty() {
                evidence.push(format!(
                    "exec_markers={}",
                    single_quoted_list_repr(&matched_exec_markers)
                ));
            }
            if !matched_download_markers.is_empty() {
                evidence.push(format!(
                    "download_markers={}",
                    single_quoted_list_repr(&matched_download_markers)
                ));
            }
            if !matched_exec_keys.is_empty() {
                evidence.push(format!(
                    "exec_keys={}",
                    single_quoted_list_repr(&matched_exec_keys)
                ));
            }
            if !matched_url_keys.is_empty() {
                evidence.push(format!(
                    "url_keys={}",
                    single_quoted_list_repr(&matched_url_keys)
                ));
            }

            findings.push(self.make_finding(
                format!(
                    "Tool {} appears to combine remote download capability with command execution.",
                    single_quoted_repr(&tool.name)
                ),
                evidence,
                Some(tool.name.clone()),
                BTreeMap::new(),
            ));
        }
        findings
    }
}

// --- dangerous_fs_write_tool ---------------------------------------------

/// Rule: `dangerous_fs_write_tool`. Flags tools that look like file
/// writers (`write_file`, `save_to_disk`, ...).
pub struct FsWrite;

const FS_WRITE_MARKERS: &[&str] = &["write", "save", "append", "create", "update", "edit"];
const FS_FILE_MARKERS: &[&str] = &["file", "filesystem", "disk", "path", "directory", "folder"];

impl Rule for FsWrite {
    fn id(&self) -> &'static str {
        "dangerous_fs_write_tool"
    }
    fn title(&self) -> &'static str {
        "Dangerous filesystem write tool"
    }
    fn rationale(&self) -> &'static str {
        "Tools that write files on disk are high risk."
    }
    fn severity(&self) -> Severity {
        Severity::Error
    }
    fn category(&self) -> FindingCategory {
        FindingCategory::Capability
    }
    fn risk_category(&self) -> RiskCategory {
        RiskCategory::FileSystem
    }
    fn bucket(&self) -> ScoreBucket {
        ScoreBucket::Security
    }
    fn tags(&self) -> &'static [&'static str] {
        &["capability", "filesystem"]
    }

    fn evaluate(&self, server: &NormalizedServer) -> Vec<Finding> {
        let mut findings = Vec::new();
        for tool in &server.tools {
            let name = normalize_text(Some(&tool.name));
            let description = normalize_text(tool.description.as_deref());
            let property_names = schema_property_names(&tool.input_schema);

            let matched_write: Vec<&str> = FS_WRITE_MARKERS
                .iter()
                .copied()
                .filter(|m| name.contains(m))
                .collect();
            let matched_file: Vec<&str> = FS_FILE_MARKERS
                .iter()
                .copied()
                .filter(|m| name.contains(m) || description.contains(m))
                .collect();
            let matched_path = matching_keys(&property_names, PATH_KEYS);
            let matched_content = matching_keys(&property_names, CONTENT_KEYS);

            if matched_write.is_empty() || matched_file.is_empty() || matched_path.is_empty() {
                continue;
            }

            let mut evidence = vec![
                format!("write_markers={}", single_quoted_list_repr(&matched_write)),
                format!("file_markers={}", single_quoted_list_repr(&matched_file)),
                format!("path_keys={}", single_quoted_list_repr(&matched_path)),
            ];
            if !matched_content.is_empty() {
                evidence.push(format!(
                    "content_keys={}",
                    single_quoted_list_repr(&matched_content)
                ));
            }

            findings.push(self.make_finding(
                format!(
                    "Tool {} appears to provide filesystem write access.",
                    single_quoted_repr(&tool.name)
                ),
                evidence,
                Some(tool.name.clone()),
                BTreeMap::new(),
            ));
        }
        findings
    }
}

// --- dangerous_fs_delete_tool --------------------------------------------

/// Rule: `dangerous_fs_delete_tool`. Stricter than [`FsWrite`] — requires
/// both the name and description to tokenise one of the explicit delete
/// verbs, so accidental matches on nouns like `deletion_log` are avoided.
pub struct FsDelete;

const FS_DELETE_MARKERS: &[&str] = &["delete", "remove", "rm", "unlink", "erase", "truncate"];

impl Rule for FsDelete {
    fn id(&self) -> &'static str {
        "dangerous_fs_delete_tool"
    }
    fn title(&self) -> &'static str {
        "Dangerous filesystem delete tool"
    }
    fn rationale(&self) -> &'static str {
        "Tools that delete files or directories are high risk."
    }
    fn severity(&self) -> Severity {
        Severity::Error
    }
    fn category(&self) -> FindingCategory {
        FindingCategory::Capability
    }
    fn risk_category(&self) -> RiskCategory {
        RiskCategory::FileSystem
    }
    fn bucket(&self) -> ScoreBucket {
        ScoreBucket::Security
    }
    fn tags(&self) -> &'static [&'static str] {
        &["capability", "filesystem", "destructive"]
    }

    fn evaluate(&self, server: &NormalizedServer) -> Vec<Finding> {
        let mut findings = Vec::new();
        for tool in &server.tools {
            let name = normalize_text(Some(&tool.name));
            let description = normalize_text(tool.description.as_deref());
            let property_names = schema_property_names(&tool.input_schema);

            // Tokenise so we only match on whole words — a description
            // mentioning "undelete" should not fire the rule.
            let name_tokens: HashSet<String> = alnum_tokens(&name).into_iter().collect();
            let description_tokens: HashSet<String> =
                alnum_tokens(&description).into_iter().collect();

            let matched_delete: Vec<&str> = FS_DELETE_MARKERS
                .iter()
                .copied()
                .filter(|m| name_tokens.contains(*m) || description_tokens.contains(*m))
                .collect();
            let matched_file: Vec<&str> = FS_FILE_MARKERS
                .iter()
                .copied()
                .filter(|m| name.contains(m) || description.contains(m))
                .collect();
            let matched_path = matching_keys(&property_names, PATH_KEYS);

            if matched_delete.is_empty() || matched_file.is_empty() || matched_path.is_empty() {
                continue;
            }

            findings.push(self.make_finding(
                format!(
                    "Tool {} appears to provide filesystem delete access.",
                    single_quoted_repr(&tool.name)
                ),
                vec![
                    format!(
                        "delete_markers={}",
                        single_quoted_list_repr(&matched_delete)
                    ),
                    format!("file_markers={}", single_quoted_list_repr(&matched_file)),
                    format!("path_keys={}", single_quoted_list_repr(&matched_path)),
                ],
                Some(tool.name.clone()),
                BTreeMap::new(),
            ));
        }
        findings
    }
}

// --- dangerous_http_request_tool -----------------------------------------

/// Rule: `dangerous_http_request_tool`. Flags tools that exhibit the
/// "generic HTTP client" pattern — URL input plus fetch/request verbs.
pub struct HttpRequest;

const HTTP_NAME_MARKERS: &[&str] = &[
    "http", "fetch", "request", "post", "get", "webhook", "download", "upload",
];
const HTTP_DESC_MARKERS: &[&str] = &[
    "http request",
    "remote api",
    "webhook",
    "download",
    "upload",
    "fetch url",
    "call external",
];

impl Rule for HttpRequest {
    fn id(&self) -> &'static str {
        "dangerous_http_request_tool"
    }
    fn title(&self) -> &'static str {
        "Dangerous HTTP request tool"
    }
    fn rationale(&self) -> &'static str {
        "Tools that issue arbitrary HTTP requests are high risk."
    }
    fn severity(&self) -> Severity {
        Severity::Error
    }
    fn category(&self) -> FindingCategory {
        FindingCategory::Capability
    }
    fn risk_category(&self) -> RiskCategory {
        RiskCategory::Network
    }
    fn bucket(&self) -> ScoreBucket {
        ScoreBucket::Security
    }
    fn tags(&self) -> &'static [&'static str] {
        &["capability", "network", "http"]
    }

    fn evaluate(&self, server: &NormalizedServer) -> Vec<Finding> {
        let mut findings = Vec::new();
        for tool in &server.tools {
            let name = normalize_text(Some(&tool.name));
            let description = normalize_text(tool.description.as_deref());
            let property_names = schema_property_names(&tool.input_schema);

            let matched_name: Vec<&str> = HTTP_NAME_MARKERS
                .iter()
                .copied()
                .filter(|m| name.contains(m))
                .collect();
            let matched_desc: Vec<&str> = HTTP_DESC_MARKERS
                .iter()
                .copied()
                .filter(|m| description.contains(m))
                .collect();
            let matched_url_keys = matching_keys(&property_names, URL_KEYS);

            if matched_url_keys.is_empty() {
                continue;
            }
            if matched_name.is_empty() && matched_desc.is_empty() {
                continue;
            }

            let mut evidence = vec![format!(
                "url_keys={}",
                single_quoted_list_repr(&matched_url_keys)
            )];
            if !matched_name.is_empty() {
                evidence.push(format!(
                    "name_markers={}",
                    single_quoted_list_repr(&matched_name)
                ));
            }
            if !matched_desc.is_empty() {
                evidence.push(format!(
                    "description_markers={}",
                    single_quoted_list_repr(&matched_desc)
                ));
            }

            findings.push(self.make_finding(
                format!(
                    "Tool {} appears to expose outbound HTTP request capability.",
                    single_quoted_repr(&tool.name)
                ),
                evidence,
                Some(tool.name.clone()),
                BTreeMap::new(),
            ));
        }
        findings
    }
}

// --- dangerous_network_tool ----------------------------------------------

/// Rule: `dangerous_network_tool`. Broader than [`HttpRequest`] — catches
/// lower-level networking primitives (sockets, proxies, tunnels).
pub struct Network;

const NET_NAME_MARKERS: &[&str] = &[
    "connect", "socket", "proxy", "tunnel", "forward", "listen", "tcp", "udp",
];
const NET_DESC_MARKERS: &[&str] = &[
    "network",
    "socket",
    "tcp",
    "udp",
    "port",
    "remote host",
    "proxy",
    "tunnel",
];

impl Rule for Network {
    fn id(&self) -> &'static str {
        "dangerous_network_tool"
    }
    fn title(&self) -> &'static str {
        "Dangerous network tool"
    }
    fn rationale(&self) -> &'static str {
        "Tools that expose generic network access are high risk."
    }
    fn severity(&self) -> Severity {
        Severity::Error
    }
    fn category(&self) -> FindingCategory {
        FindingCategory::Capability
    }
    fn risk_category(&self) -> RiskCategory {
        RiskCategory::Network
    }
    fn bucket(&self) -> ScoreBucket {
        ScoreBucket::Security
    }
    fn tags(&self) -> &'static [&'static str] {
        &["capability", "network"]
    }

    fn evaluate(&self, server: &NormalizedServer) -> Vec<Finding> {
        // `URL_KEYS ∪ {port, address}` — network rules accept both HTTP and
        // lower-level connection metadata.
        let mut network_keys_vec: Vec<&'static str> = URL_KEYS.to_vec();
        network_keys_vec.push("port");
        network_keys_vec.push("address");

        let mut findings = Vec::new();
        for tool in &server.tools {
            let name = normalize_text(Some(&tool.name));
            let description = normalize_text(tool.description.as_deref());
            let property_names = schema_property_names(&tool.input_schema);

            let matched_name: Vec<&str> = NET_NAME_MARKERS
                .iter()
                .copied()
                .filter(|m| name.contains(m))
                .collect();
            let matched_desc: Vec<&str> = NET_DESC_MARKERS
                .iter()
                .copied()
                .filter(|m| description.contains(m))
                .collect();
            let matched_network_keys = matching_keys(&property_names, &network_keys_vec);

            if matched_name.is_empty() {
                continue;
            }
            if matched_desc.is_empty() && matched_network_keys.is_empty() {
                continue;
            }

            let mut evidence = vec![format!(
                "name_markers={}",
                single_quoted_list_repr(&matched_name)
            )];
            if !matched_desc.is_empty() {
                evidence.push(format!(
                    "description_markers={}",
                    single_quoted_list_repr(&matched_desc)
                ));
            }
            if !matched_network_keys.is_empty() {
                evidence.push(format!(
                    "network_keys={}",
                    single_quoted_list_repr(&matched_network_keys)
                ));
            }

            findings.push(self.make_finding(
                format!(
                    "Tool {} appears to expose generic network connectivity.",
                    single_quoted_repr(&tool.name)
                ),
                evidence,
                Some(tool.name.clone()),
                BTreeMap::new(),
            ));
        }
        findings
    }
}

// --- write_tool_without_scope_hint ---------------------------------------

/// Rule: `write_tool_without_scope_hint`. Flags filesystem-mutating tools
/// that do not advertise any scope restriction (e.g. "writes within the
/// project directory only").
pub struct UnscopedWrite;

const UW_WRITE_MARKERS: &[&str] = &["write", "save", "append", "create", "update", "edit"];
const UW_DELETE_MARKERS: &[&str] = &["delete", "remove", "unlink", "erase", "truncate"];

impl Rule for UnscopedWrite {
    fn id(&self) -> &'static str {
        "write_tool_without_scope_hint"
    }
    fn title(&self) -> &'static str {
        "Write tool without scope hint"
    }
    fn rationale(&self) -> &'static str {
        "Filesystem mutation tools should document scope constraints clearly."
    }
    fn severity(&self) -> Severity {
        Severity::Warning
    }
    fn category(&self) -> FindingCategory {
        FindingCategory::Capability
    }
    fn risk_category(&self) -> RiskCategory {
        RiskCategory::ExternalSideEffects
    }
    fn bucket(&self) -> ScoreBucket {
        ScoreBucket::Ergonomics
    }
    fn tags(&self) -> &'static [&'static str] {
        &["capability", "filesystem", "scope"]
    }

    fn evaluate(&self, server: &NormalizedServer) -> Vec<Finding> {
        let mut findings = Vec::new();
        for tool in &server.tools {
            let name = normalize_text(Some(&tool.name));
            let description = normalize_text(tool.description.as_deref());
            let property_names = schema_property_names(&tool.input_schema);

            let has_write_marker = UW_WRITE_MARKERS.iter().any(|m| name.contains(m));
            let has_delete_marker = UW_DELETE_MARKERS
                .iter()
                .any(|m| name.contains(m) || description.contains(m));
            let has_file_marker = FS_FILE_MARKERS
                .iter()
                .any(|m| name.contains(m) || description.contains(m));
            let matched_path = matching_keys(&property_names, PATH_KEYS);

            if !(has_write_marker || has_delete_marker) {
                continue;
            }
            if !has_file_marker || matched_path.is_empty() {
                continue;
            }
            if has_scope_hint(tool.description.as_deref(), &tool.input_schema) {
                continue;
            }

            findings.push(self.make_finding(
                format!(
                    "Tool {} modifies the filesystem without any visible scope hint.",
                    single_quoted_repr(&tool.name)
                ),
                vec![
                    format!("path_keys={}", single_quoted_list_repr(&matched_path)),
                    "scope_hint=<missing>".to_string(),
                ],
                Some(tool.name.clone()),
                BTreeMap::new(),
            ));
        }
        findings
    }
}

// --- tool_description_mentions_destructive_access ------------------------

/// Rule: `tool_description_mentions_destructive_access`. Flags
/// descriptions that explicitly advertise broad destructive behaviour
/// — e.g. "delete any file on the host machine".
pub struct DestructiveDescription;

const DD_DESTRUCTIVE_MARKERS: &[&str] = &[
    "delete",
    "remove",
    "erase",
    "overwrite",
    "truncate",
    "destroy",
];
const DD_BROAD_SCOPE_MARKERS: &[&str] = &[
    "arbitrary",
    "any file",
    "any directory",
    "host machine",
    "without validation",
];

impl Rule for DestructiveDescription {
    fn id(&self) -> &'static str {
        "tool_description_mentions_destructive_access"
    }
    fn title(&self) -> &'static str {
        "Description mentions destructive access"
    }
    fn rationale(&self) -> &'static str {
        "Tool descriptions should make destructive broad-scope access easy to spot."
    }
    fn severity(&self) -> Severity {
        Severity::Warning
    }
    fn category(&self) -> FindingCategory {
        FindingCategory::Capability
    }
    fn risk_category(&self) -> RiskCategory {
        RiskCategory::ExternalSideEffects
    }
    fn bucket(&self) -> ScoreBucket {
        ScoreBucket::Metadata
    }
    fn tags(&self) -> &'static [&'static str] {
        &["tools", "description", "destructive"]
    }

    fn evaluate(&self, server: &NormalizedServer) -> Vec<Finding> {
        let mut findings = Vec::new();
        for tool in &server.tools {
            let description = normalize_text(tool.description.as_deref());
            if description.is_empty() {
                continue;
            }
            let matched_destructive: Vec<&str> = DD_DESTRUCTIVE_MARKERS
                .iter()
                .copied()
                .filter(|m| description.contains(m))
                .collect();
            let matched_scope: Vec<&str> = DD_BROAD_SCOPE_MARKERS
                .iter()
                .copied()
                .filter(|m| description.contains(m))
                .collect();
            if matched_destructive.is_empty() || matched_scope.is_empty() {
                continue;
            }

            findings.push(self.make_finding(
                format!(
                    "Tool {} description explicitly advertises broad destructive access.",
                    single_quoted_repr(&tool.name)
                ),
                vec![
                    format!(
                        "destructive_markers={}",
                        single_quoted_list_repr(&matched_destructive)
                    ),
                    format!("scope_markers={}", single_quoted_list_repr(&matched_scope)),
                ],
                Some(tool.name.clone()),
                BTreeMap::new(),
            ));
        }
        findings
    }
}

// --- response_too_large --------------------------------------------------

/// Rule: `response_too_large`. Reads [`NormalizedServer::response_sizes`]
/// (populated by the transport layer during discovery) and reports when
/// a single JSON-RPC response crosses one of two thresholds:
///
/// * `>= 256 KiB` → `WARNING` (context-hungry).
/// * `>= 1 MiB`   → `ERROR` (will eventually OOM the scanner itself).
pub struct ResponseTooLarge;

pub const RESPONSE_WARNING_THRESHOLD: u64 = 256 * 1024;
pub const RESPONSE_ERROR_THRESHOLD: u64 = 1024 * 1024;

impl Rule for ResponseTooLarge {
    fn id(&self) -> &'static str {
        "response_too_large"
    }
    fn title(&self) -> &'static str {
        "Response too large"
    }
    fn rationale(&self) -> &'static str {
        "MCP servers should keep discovery responses small so agent contexts stay usable."
    }
    fn severity(&self) -> Severity {
        // Per-finding severity is picked from size thresholds inside
        // `evaluate`; this value only drives SARIF
        // `defaultConfiguration.level` for the rule descriptor.
        Severity::Warning
    }
    fn category(&self) -> FindingCategory {
        FindingCategory::Capability
    }
    fn risk_category(&self) -> RiskCategory {
        RiskCategory::MetadataHygiene
    }
    fn bucket(&self) -> ScoreBucket {
        ScoreBucket::Ergonomics
    }
    fn tags(&self) -> &'static [&'static str] {
        &["transport", "size"]
    }

    fn evaluate(&self, server: &NormalizedServer) -> Vec<Finding> {
        let mut findings = Vec::new();
        for (method, size) in &server.response_sizes {
            let severity = if *size >= RESPONSE_ERROR_THRESHOLD {
                Severity::Error
            } else if *size >= RESPONSE_WARNING_THRESHOLD {
                Severity::Warning
            } else {
                continue;
            };

            let threshold_kib = match severity {
                Severity::Error => RESPONSE_ERROR_THRESHOLD / 1024,
                _ => RESPONSE_WARNING_THRESHOLD / 1024,
            };
            let message = format!(
                "Response to {method} is {size} bytes — above the {threshold_kib} KiB threshold."
            );
            let evidence = vec![
                format!("method={method}"),
                format!("response_bytes={size}"),
                format!("warning_threshold={RESPONSE_WARNING_THRESHOLD}"),
                format!("error_threshold={RESPONSE_ERROR_THRESHOLD}"),
            ];

            // Build the Finding by hand so severity can vary per response
            // size (the trait's `make_finding` always uses `self.severity()`).
            findings.push(Finding {
                rule_id: self.id().to_string(),
                level: severity,
                title: Some(self.title().to_string()),
                message,
                category: self.category(),
                risk_category: self.risk_category(),
                bucket: self.bucket(),
                evidence,
                penalty: severity.score_impact(),
                tool_name: None,
                prompt_name: None,
                metadata: BTreeMap::new(),
            });
        }
        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::NormalizedTool;

    fn with_schema(
        name: &str,
        description: Option<&str>,
        schema: serde_json::Value,
    ) -> NormalizedTool {
        NormalizedTool {
            name: name.to_string(),
            description: description.map(String::from),
            input_schema: schema,
            metadata: BTreeMap::new(),
        }
    }

    #[test]
    fn exec_tool_fires_on_shell_command_pattern() {
        let mut server = NormalizedServer::new("test");
        server.tools.push(with_schema(
            "shell_exec",
            Some("execute a shell command"),
            serde_json::json!({
                "type": "object",
                "properties": {"command": {"type": "string"}}
            }),
        ));
        assert_eq!(ExecTool.evaluate(&server).len(), 1);
    }

    #[test]
    fn exec_tool_skips_without_name_marker() {
        let mut server = NormalizedServer::new("test");
        server.tools.push(with_schema(
            "read_file",
            Some("execute a shell command"),
            serde_json::json!({"type": "object", "properties": {"command": {}}}),
        ));
        assert!(ExecTool.evaluate(&server).is_empty());
    }

    #[test]
    fn shell_download_exec_fires_on_curl_pipe_sh() {
        let mut server = NormalizedServer::new("test");
        server.tools.push(with_schema(
            "shell_install",
            Some("download remote script and run it"),
            serde_json::json!({
                "type": "object",
                "properties": {"url": {}, "command": {}}
            }),
        ));
        assert_eq!(ShellDownloadExec.evaluate(&server).len(), 1);
    }

    #[test]
    fn fs_write_fires_on_write_file_pattern() {
        let mut server = NormalizedServer::new("test");
        server.tools.push(with_schema(
            "write_file",
            Some("save a file to disk"),
            serde_json::json!({
                "type": "object",
                "properties": {"path": {}, "content": {}}
            }),
        ));
        assert_eq!(FsWrite.evaluate(&server).len(), 1);
    }

    #[test]
    fn fs_delete_fires_on_remove_file_pattern() {
        let mut server = NormalizedServer::new("test");
        server.tools.push(with_schema(
            "remove_file",
            Some("delete a file from disk"),
            serde_json::json!({"type": "object", "properties": {"path": {}}}),
        ));
        assert_eq!(FsDelete.evaluate(&server).len(), 1);
    }

    #[test]
    fn http_request_fires_on_url_and_fetch() {
        let mut server = NormalizedServer::new("test");
        server.tools.push(with_schema(
            "http_fetch",
            Some("download from remote api"),
            serde_json::json!({"type": "object", "properties": {"url": {}}}),
        ));
        assert_eq!(HttpRequest.evaluate(&server).len(), 1);
    }

    #[test]
    fn network_fires_on_socket_pattern() {
        let mut server = NormalizedServer::new("test");
        server.tools.push(with_schema(
            "socket_connect",
            Some("opens a tcp socket to a remote host"),
            serde_json::json!({
                "type": "object",
                "properties": {"host": {}, "port": {}}
            }),
        ));
        assert_eq!(Network.evaluate(&server).len(), 1);
    }

    #[test]
    fn unscoped_write_fires_without_scope_hint() {
        let mut server = NormalizedServer::new("test");
        server.tools.push(with_schema(
            "write_file",
            Some("writes a file"),
            serde_json::json!({"type": "object", "properties": {"path": {}}}),
        ));
        assert_eq!(UnscopedWrite.evaluate(&server).len(), 1);
    }

    #[test]
    fn unscoped_write_skips_when_workspace_mentioned() {
        let mut server = NormalizedServer::new("test");
        server.tools.push(with_schema(
            "write_file",
            Some("writes a file inside the workspace"),
            serde_json::json!({"type": "object", "properties": {"path": {}}}),
        ));
        assert!(UnscopedWrite.evaluate(&server).is_empty());
    }

    #[test]
    fn destructive_description_fires_on_broad_scope() {
        let mut server = NormalizedServer::new("test");
        server.tools.push(with_schema(
            "nuke",
            Some("delete any file on the host machine"),
            serde_json::json!({}),
        ));
        assert_eq!(DestructiveDescription.evaluate(&server).len(), 1);
    }

    #[test]
    fn response_too_large_silent_below_threshold() {
        let mut server = NormalizedServer::new("test");
        server
            .response_sizes
            .insert("tools/list".to_string(), 10_000);
        assert!(ResponseTooLarge.evaluate(&server).is_empty());
    }

    #[test]
    fn response_too_large_warns_at_256_kib() {
        let mut server = NormalizedServer::new("test");
        server
            .response_sizes
            .insert("tools/list".to_string(), RESPONSE_WARNING_THRESHOLD);
        let findings = ResponseTooLarge.evaluate(&server);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].level, Severity::Warning);
        assert_eq!(findings[0].penalty, 10);
    }

    #[test]
    fn response_too_large_errors_at_1_mib() {
        let mut server = NormalizedServer::new("test");
        server
            .response_sizes
            .insert("tools/list".to_string(), RESPONSE_ERROR_THRESHOLD);
        let findings = ResponseTooLarge.evaluate(&server);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].level, Severity::Error);
        assert_eq!(findings[0].penalty, 20);
    }
}
