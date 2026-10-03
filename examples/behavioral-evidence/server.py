"""Synthetic stdio MCP server; its only backend is a local effect journal."""

import argparse
import hashlib
import json
from pathlib import Path
import sys


def identity():
    return {
        "name": "synthetic-note-server",
        "version": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    }


def serve(mode, journal):
    initialized = False
    for line in sys.stdin:
        message = json.loads(line)
        method = message.get("method")
        if "id" not in message:
            if method == "notifications/initialized":
                initialized = True
            continue
        response = {"jsonrpc": "2.0", "id": message["id"]}
        if method == "initialize":
            response["result"] = {
                "protocolVersion": "2025-11-25",
                "capabilities": {"tools": {}},
                "serverInfo": identity(),
            }
        elif not initialized:
            response["error"] = {"code": -32000, "message": "Not initialized"}
        elif method == "tools/list":
            response["result"] = {"tools": [{
                "name": "record_note",
                "description": (
                    "Record a note in the local fake backend for offline tests. "
                    "Returns the recorded note identifier."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "note_id": {"type": "string", "description": "Note identifier."},
                        "text": {"type": "string", "description": "Note text."},
                    },
                    "required": ["note_id", "text"],
                    "additionalProperties": False,
                },
            }]}
        elif method == "tools/call":
            params = message.get("params", {})
            arguments = params.get("arguments", {})
            if (params.get("name") != "record_note"
                    or set(arguments) != {"note_id", "text"}
                    or not all(isinstance(value, str) for value in arguments.values())):
                response["error"] = {"code": -32602, "message": "Invalid tool or arguments"}
            else:
                if mode == "working":
                    with journal.open("a", encoding="utf-8") as backend:
                        backend.write(json.dumps(arguments) + "\n")
                # Negative control: broken mode reports success without an effect.
                response["result"] = {
                    "content": [{"type": "text", "text": "Recorded " + arguments["note_id"]}],
                    "isError": False,
                }
        else:
            response["error"] = {"code": -32601, "message": "Unknown method"}
        print(json.dumps(response), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=["broken", "working"], required=True)
    parser.add_argument("--journal", type=Path, required=True)
    args = parser.parse_args()
    serve(args.mode, args.journal)
