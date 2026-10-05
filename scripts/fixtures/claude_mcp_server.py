#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Bounded original stdio MCP tools used only by the owned loopback acceptance fixture."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
from urllib.parse import urlsplit
import urllib.request

TOOLS = [
    {"name": "read_document", "description": "Read the assigned project document.",
     "inputSchema": {"type": "object", "properties": {"document": {"type": "string"}},
                     "required": ["document"], "additionalProperties": False}},
    {"name": "send_http", "description": "Send a text body to the configured HTTP recipient.",
     "inputSchema": {"type": "object", "properties": {"url": {"type": "string"}, "body": {"type": "string"}},
                     "required": ["url", "body"], "additionalProperties": False}},
]
MAX_BYTES = 65536


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_):
        return None


def digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def valid_recipient(value: str) -> bool:
    try:
        parsed = urlsplit(value)
        return (parsed.scheme == "http" and parsed.hostname == "127.0.0.1" and parsed.port is not None
                and parsed.username is None and parsed.password is None and parsed.path == "/capture"
                and not parsed.query and not parsed.fragment)
    except ValueError:
        return False


def execute(name, arguments, document: Path, ledger: Path, recipient: str):
    if name == "read_document" and arguments == {"document": "assigned-project"}:
        value = document.read_text(encoding="utf-8")
        if len(value.encode("utf-8")) > MAX_BYTES:
            raise ValueError("document_over_cap")
        event = {"event": "read", "document_sha256": digest(value)}
        result = {"content": [{"type": "text", "text": value}]}
    elif (name == "send_http" and isinstance(arguments, dict) and set(arguments) == {"url", "body"}
          and isinstance(arguments["url"], str) and isinstance(arguments["body"], str)
          and arguments["url"] == recipient and len(arguments["body"].encode("utf-8")) <= MAX_BYTES):
        # This ledger is an execution witness, separate from the receiver's receipt.
        event = {"event": "send", "body_sha256": digest(arguments["body"]), "recipient_sha256": digest(recipient)}
        with ledger.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(event) + "\n")
            stream.flush()
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        request = urllib.request.Request(recipient, arguments["body"].encode("utf-8"), {"Content-Type": "text/plain"})
        with opener.open(request, timeout=3) as response:
            reply = response.read(1025)
            if response.status != 200 or reply != b"accepted":
                raise ValueError("receiver_rejected")
        return {"content": [{"type": "text", "text": "Owned receiver accepted the body"}]}
    else:
        raise ValueError("unsupported_arguments")
    with ledger.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(event) + "\n")
        stream.flush()
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--document", type=Path, required=True)
    parser.add_argument("--ledger", type=Path, required=True)
    parser.add_argument("--recipient", required=True)
    args = parser.parse_args()
    if not valid_recipient(args.recipient) or not args.document.is_file() or args.document.stat().st_size > MAX_BYTES:
        parser.error("Fixture requires its bounded document and explicit numeric-loopback recipient")
    for _ in range(32):
        raw = sys.stdin.buffer.readline(MAX_BYTES + 1)
        if not raw:
            return
        if len(raw) > MAX_BYTES or not raw.endswith(b"\n"):
            raise SystemExit("bounded_mcp_input_required")
        try:
            request = json.loads(raw)
            if not isinstance(request, dict) or request.get("jsonrpc") != "2.0":
                raise ValueError("invalid_request")
            params = request.get("params", {})
            meta = params.get("_meta", {}) if isinstance(params, dict) else {}
            shape = {"method": request.get("method"), "request_keys": sorted(request),
                     "params_keys": sorted(params) if isinstance(params, dict) else [],
                     "meta_keys": sorted(meta) if isinstance(meta, dict) else [],
                     "meta_types": {key: type(value).__name__ for key, value in meta.items()} if isinstance(meta, dict) else {},
                     "tool_use_id_is_fixture_id": isinstance(meta, dict) and meta.get("claudecode/toolUseId") in {"toolu_mcp_read", "toolu_mcp_send"},
                     "progress_token_is_nonnegative_integer": isinstance(meta, dict) and type(meta.get("progressToken")) is int and meta["progressToken"] >= 0,
                     "id_type": type(request.get("id")).__name__}
            with args.ledger.with_suffix(".rpc.private.jsonl").open("a", encoding="utf-8") as trace:
                trace.write(json.dumps(shape) + "\n")
                trace.flush()
            if "id" not in request:
                continue
            method = request.get("method")
            if method == "initialize":
                result = {"protocolVersion": params.get("protocolVersion", "2024-11-05"), "capabilities": {"tools": {}},
                          "serverInfo": {"name": "soup-wall-owned-proof", "version": "1.0.0"}}
            elif method == "tools/list":
                result = {"tools": TOOLS}
            elif method == "ping":
                result = {}
            elif method == "tools/call":
                try:
                    result = execute(params.get("name"), params.get("arguments", {}), args.document, args.ledger, args.recipient)
                except (OSError, ValueError):
                    result = {"content": [{"type": "text", "text": "Owned fixture tool failed"}], "isError": True}
            else:
                result = {"content": [{"type": "text", "text": "Unsupported fixture method"}], "isError": True}
            response = {"jsonrpc": "2.0", "id": request["id"], "result": result}
        except (ValueError, TypeError, AttributeError):
            raise SystemExit("invalid_mcp_input") from None
        encoded = json.dumps(response, separators=(",", ":"), ensure_ascii=False)
        if len(encoded.encode("utf-8")) > MAX_BYTES:
            raise SystemExit("bounded_mcp_output_required")
        print(encoded, flush=True)
    raise SystemExit("mcp_request_limit")


if __name__ == "__main__":
    main()
