"""Compose an unchanged mcpunit audit with independent behavioral evidence."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import uuid

from server import identity


def timestamp():
    return datetime.now(timezone.utc).isoformat()


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path, value):
    # Replace atomically so interrupted writes cannot look like complete reports.
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def reference(path):
    return {"path": path.name, "sha256": digest(path)}


def check_behavior(command, cwd, expected_identity, journal, timeout):
    """Use a fresh process with exactly the same server command and configuration.

    The three messages are ordered on stdin. This synthetic server handles them
    synchronously; this is a fixture client, not a general-purpose MCP client.
    subprocess.run kills and reaps the process if it exceeds the deadline.
    """
    expected = {"note_id": "fixture-note", "text": "Hello from the offline fixture"}
    messages = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-11-25", "capabilities": {},
            "clientInfo": {"name": "independent-behavior-fixture", "version": "1"},
        }},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {
            "name": "record_note", "arguments": expected,
        }},
    ]
    completed = subprocess.run(
        command, cwd=cwd, input="".join(json.dumps(m) + "\n" for m in messages),
        capture_output=True, text=True, encoding="utf-8", timeout=timeout, check=True,
    )
    replies = [json.loads(line) for line in completed.stdout.splitlines()]
    if (len(replies) != 2 or not all(isinstance(r, dict) for r in replies)
            or [r.get("id") for r in replies] != [1, 2]
            or any(r.get("jsonrpc") != "2.0" or "error" in r for r in replies)):
        raise ValueError("The fixture did not receive both successful JSON-RPC responses")
    if not all(isinstance(r.get("result"), dict) for r in replies):
        raise ValueError("The fixture received a malformed response result")
    if replies[0]["result"].get("serverInfo") != expected_identity:
        raise ValueError("Behavioral server identity differs from the audited server")
    result = replies[1]["result"]
    events = [json.loads(line) for line in journal.read_text(encoding="utf-8").splitlines()]
    assertions = [
        {"name": "tool_reports_success", "passed": result.get("isError") is False},
        {"name": "expected_note_recorded_exactly_once", "passed": events == [expected]},
    ]
    return {
        "status": "passed" if all(a["passed"] for a in assertions) else "failed",
        "assertions": assertions,
        "expected_events": [expected],
        "observed_events": events,
        "tool_result": result,
    }


def compose(binary, output, mode, skip_behavior=False, timeout=5):
    # Each invocation gets a fresh directory and backend; previous evidence is
    # never overwritten or accidentally reused as a passing result.
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    journal = output / "effects.jsonl"
    journal.write_text("", encoding="utf-8")
    server = Path(__file__).with_name("server.py").resolve()
    config = {
        "command": [sys.executable, str(server), "--mode", mode, "--journal", str(journal)],
        "cwd": str(output),
    }
    subject = {
        "server": identity(),
        "revision": {"kind": "source-sha256", "value": digest(server)},
        "configuration": config,
        "configuration_sha256": hashlib.sha256(
            json.dumps(config, sort_keys=True).encode("utf-8")
        ).hexdigest(),
    }
    manifest_path = output / "manifest.json"
    behavior_path = output / "behavior.json"
    manifest = {
        "schema": "mcpunit-behavior-composition-example/v1",
        "composition_id": str(uuid.uuid4()),
        "created_at": timestamp(),
        "subject": subject,
        "audit": {"status": "incomplete", "scope": "metadata-and-schema"},
        "behavior": {"status": "missing", "run_id": None, "report": None},
    }
    write_json(manifest_path, manifest)
    try:
        audit_path = output / "audit.json"
        audit = subprocess.run(
            [str(binary.resolve()), "--log", "warn", "test", "--min-score", "100",
             "--cwd", str(output), "--timeout", str(timeout),
             "--json-out", str(audit_path), "--sarif-out", str(output / "audit.sarif"),
             "--markdown-out", str(output / "audit.md"), "--cmd", *config["command"]],
            capture_output=True, text=True, encoding="utf-8", timeout=timeout * 4,
        )
        (output / "audit.txt").write_text(audit.stdout, encoding="utf-8")
        if audit.returncode != 0:
            raise ValueError(f"Metadata audit exited {audit.returncode}: {audit.stderr.strip()}")
        report = json.loads(audit_path.read_text(encoding="utf-8"))
        if report["test"]["target"]["server"]["name"] != subject["server"]["name"] or (
            report["test"]["target"]["server"]["version"] != subject["server"]["version"]
        ):
            raise ValueError("Audit server identity differs from the selected revision")
        if journal.read_text(encoding="utf-8"):
            raise ValueError("Metadata discovery unexpectedly changed the effect journal")
        if digest(server) != subject["revision"]["value"]:
            raise ValueError("Server source changed during the audit")
        manifest["audit"].update({
            "status": "completed", "exit_code": audit.returncode,
            "total_score": report["audit"]["total_score"]["value"],
            "report": reference(audit_path),
        })
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        manifest["audit"]["reason"] = str(error)
        write_json(manifest_path, manifest)
        return 2
    write_json(manifest_path, manifest)
    if skip_behavior:
        manifest["behavior"]["reason"] = "Behavioral fixture explicitly skipped"
        write_json(manifest_path, manifest)
        return 2

    behavior = {
        "schema": "independent-behavior-fixture-example/v1",
        "run_id": str(uuid.uuid4()), "started_at": timestamp(),
        "subject": subject, "fixture_sha256": digest(Path(__file__)),
        "status": "incomplete", "assertions": [],
    }
    write_json(behavior_path, behavior)
    manifest["behavior"] = {
        "status": "incomplete", "run_id": behavior["run_id"],
        "report": {"path": behavior_path.name},
    }
    write_json(manifest_path, manifest)
    try:
        behavior.update(check_behavior(
            config["command"], output, subject["server"], journal, timeout,
        ))
        if digest(server) != subject["revision"]["value"]:
            raise ValueError("Server source changed during the behavioral run")
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        behavior.update({"status": "incomplete", "reason": str(error)})
    try:
        behavior["effect_journal"] = reference(journal)
    except OSError as error:
        behavior["status"] = "incomplete"
        behavior.setdefault("reason", f"Effect journal unavailable during finalization: {error}")
        behavior["effect_journal"] = {"path": journal.name, "reason": str(error)}
    behavior["finished_at"] = timestamp()
    write_json(behavior_path, behavior)
    manifest["behavior"].update({
        "status": behavior["status"], "report": reference(behavior_path),
    })
    write_json(manifest_path, manifest)
    return {"passed": 0, "failed": 1, "incomplete": 2}[behavior["status"]]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mcpunit", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True, help="New output directory")
    parser.add_argument("--mode", choices=["broken", "working"], default="broken")
    parser.add_argument("--skip-behavior", action="store_true")
    args = parser.parse_args()
    code = compose(args.mcpunit, args.out, args.mode, args.skip_behavior)
    manifest = json.loads((args.out / "manifest.json").read_text(encoding="utf-8"))
    print(f"audit={manifest['audit']['status']}; behavior={manifest['behavior']['status']}")
    print(f"Reports: {args.out / 'manifest.json'}")
    return code


if __name__ == "__main__":
    sys.exit(main())
