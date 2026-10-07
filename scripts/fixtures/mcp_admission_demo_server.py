#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Harmless stdio MCP server for the admission demonstration; local files and loopback only."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys
import urllib.request

TOOLS = [
    {"name": "read_document", "description": "Read a project note.",
     "inputSchema": {"type": "object", "properties": {"name": {"type": "string"}},
                     "required": ["name"], "additionalProperties": False}},
    {"name": "send_http", "description": "Send a text body to the configured local recipient.",
     "inputSchema": {"type": "object", "properties": {"url": {"type": "string"}, "body": {"type": "string"}},
                     "required": ["url", "body"], "additionalProperties": False}},
    {"name": "delete_note", "description": "Delete a project note.",
     "inputSchema": {"type": "object", "properties": {"name": {"type": "string"}},
                     "required": ["name"], "additionalProperties": False}},
]
NOTE = re.compile(r"^[a-z-]{1,32}$")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_):
        return None


def execute(name, arguments, notes: Path, recipient: str) -> str:
    if name in ("read_document", "delete_note") and NOTE.fullmatch(arguments.get("name", "")):
        note = notes / (arguments["name"] + ".txt")
        if name == "read_document":
            return note.read_text(encoding="utf-8")
        note.unlink()
        return "Deleted " + arguments["name"]
    if name == "send_http" and arguments.get("url") == recipient:
        # Only the demonstration's own loopback receiver; never a proxy or redirect.
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        request = urllib.request.Request(recipient, arguments["body"].encode("utf-8"), {"Content-Type": "text/plain"})
        with opener.open(request, timeout=3) as response:
            response.read(1024)
        return "Recipient accepted the body"
    raise ValueError("unsupported fixture arguments")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--notes", type=Path, required=True)
    parser.add_argument("--ledger", type=Path, required=True)
    parser.add_argument("--recipient", required=True)
    options = parser.parse_args()
    for raw in sys.stdin.buffer:
        request = json.loads(raw)
        method = request.get("method")
        if method == "initialize":
            result = {"protocolVersion": "2024-11-05", "capabilities": {"tools": {}},
                      "serverInfo": {"name": "soup-wall-demo", "version": "1"}}
        elif method == "tools/list":
            result = {"tools": TOOLS}
        elif method == "tools/call":
            # Execution witness: the exact original frame, written before any effect.
            with options.ledger.open("ab") as stream:
                stream.write(raw)
            params = request["params"]
            text = execute(params["name"], params["arguments"], options.notes, options.recipient)
            result = {"content": [{"type": "text", "text": text}]}
        else:
            continue
        line = json.dumps({"jsonrpc": "2.0", "id": request["id"], "result": result}, separators=(",", ":")) + "\n"
        with options.ledger.with_suffix(".responses").open("a", encoding="utf-8") as stream:
            stream.write(line)
        sys.stdout.write(line)
        sys.stdout.flush()


if __name__ == "__main__":
    main()
