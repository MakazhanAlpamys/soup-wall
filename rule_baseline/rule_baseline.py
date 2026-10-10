# SPDX-License-Identifier: Apache-2.0
"""Rule-based tool-call classifier (Task 1 baseline).

Input : {"tool_name", "raw_arguments", "server_id"?, "tool_description"?,
          "tool_schema"?, "pinned_schema"?}
Output: {"status": ok|unknown|error, "actions": [...], "unknown": bool, "confidence", "uncertainty",
         "reason_codes": [...], "reason", "scores", flags...}

Principles
- The tool description is UNTRUSTED. It never adds or removes a category. It is
  only inspected to raise flags (description_conflict, description_suspicious).
- Evidence comes from the tool name tokens, the ACTUAL arguments, and (weakly)
  the schema. Categories are multi-label; evidence is combined with noisy-OR.
- unknown is a flag, not an action: true when nothing was recognised (status
  "unknown"), on error, or when part of a shell command was not recognised
  (partial unknown, e.g. actions ["read"] + unknown true).
- No evidence -> actions [] with status "unknown". Bad input -> status "error".
  Neither is ever a permission: this module only describes the call.
- tool_schema from the server is untrusted: if it differs from pinned_schema it is
  ignored (pinned_schema is used) and confidence is capped (schema_mismatch).
"""
from __future__ import annotations

import json
import re
import sys
from typing import Any

CATEGORIES = ("read", "write", "delete", "send_data", "change_permissions")
UNKNOWN = "unknown"
THRESHOLD = 0.5
MAX_DEPTH, MAX_LEAVES, MAX_LEAF_CHARS, MAX_DESC_CHARS = 6, 200, 4096, 2000

# ---------------------------------------------------------------- name vocab
def _vocab(cat: str, words: str, weight: float = 0.7) -> dict[str, tuple[str, float]]:
    return {w: (cat, weight) for w in words.split()}

VERBS: dict[str, tuple[str, float]] = {}
VERBS.update(_vocab("read", "read get list ls cat head tail view show fetch find search lookup "
                    "query select count describe inspect preview display print load retrieve "
                    "browse stat grep glob scan open download check"))
VERBS.update(_vocab("write", "write create update edit append put set save insert add rename move "
                    "mv copy cp mkdir touch modify patch replace upsert store commit install import apply"))
VERBS.update(_vocab("delete", "delete remove rm rmdir unlink drop truncate erase purge destroy wipe "
                    "clear trash shred uninstall discard"))
VERBS.update(_vocab("send_data", "send post upload publish forward reply transmit push broadcast notify"))
VERBS.update(_vocab("send_data", "submit", 0.55))
VERBS.update(_vocab("change_permissions", "chmod chown chgrp grant revoke promote demote elevate sudo "
                    "setfacl icacls", 0.8))
# Nouns: only count when the name has no verb at all.
SEND_NOUNS = set("email mail message sms slack discord webhook notification tweet".split())
# Nouns that retarget a mutation verb: set_permissions, remove_role, revoke_access.
PERM_NOUNS = set("permission permissions perm perms role roles acl privilege privileges access grants ownership".split())
GENERIC_WRITE = set("set update add modify edit create put save replace apply patch store".split())
DELETE_VERBS = {w for w, (c, _) in VERBS.items() if c == "delete"}
READ_VERBS = {w for w, (c, _) in VERBS.items() if c == "read"}

BUILTIN = {**{n: "read" for n in "Read Grep Glob NotebookRead TodoRead WebFetch WebSearch".split()},
           **{n: "write" for n in "Write Edit MultiEdit NotebookEdit TodoWrite".split()}}
SHELL_TOKENS = set("bash shell sh zsh powershell pwsh cmd terminal exec eval".split())
SHELL_KEYS = {"command", "cmd", "argv", "script", "shell_command", "commandline", "command_line"}

# ---------------------------------------------------------------- shell rules
I = re.I
PIPE_TO_SHELL = re.compile(r"\|\s*(?:sudo\s+)?(?:ba|z)?sh\b", I)
NESTED = re.compile(r"""^(?:bash|sh|zsh)\s+-\w*c\s+(["'])(.*)\1\s*$""", I | re.S)
ENV_PREFIX = re.compile(r"^(?:\w+=\S*\s+)+")
# Ignore only complete descriptor/device targets, never filename prefixes.
NOISE_REDIRECT = re.compile(r"\d?>\s*&(?:\d+|-)(?=\s|$)|(?:\d?>>?|&>>?|>&)\s*/dev/null(?=\s|$)")
# Redirections, heredocs and process substitution are not analysed for no-op proofs.
UNSUPPORTED_SYNTAX = re.compile(r"[<>]")
REDIRECT = re.compile(r"(?<![<>\d&-])(?:&>>?|>>?&?)\s*[^\s&|>]")

DELETE_CMD = re.compile(
    r"^(?:rm|rmdir|unlink|shred|del|erase|rd|mkfs\S*|shutdown|reboot|remove-item)\b"
    r"|^git\s+(?:clean|rm)\b|^git\s+reset\s+--hard\b|^git\s+push\b.*(?:--force|\s-f\b)"
    r"|^dd\b.*\bof=/dev/|\bfind\b.*\s-delete\b|\s-exec\s+rm\b|\bxargs\s+(?:-\S+\s+)*rm\b"
    r"|\bdrop\s+(?:table|database|schema)\b|\bdelete\s+from\b|^truncate\b"
    r"|^docker\s+(?:rm|rmi|system\s+prune)\b|^kubectl\s+delete\b|^terraform\s+destroy\b", I)
PERM_CMD = re.compile(
    r"^(?:sudo|su\s+-|chmod|chown|chgrp|setfacl|icacls|takeown|usermod|passwd|visudo|setcap|chattr"
    r"|net\s+user|add-localgroupmember)\b", I)
SEND_CMD = re.compile(
    r"(?:^curl\b.*?(?:(?:--data\S*|--form\S*|--upload-file|-X\s*(?:POST|PUT|PATCH|DELETE))"
    r"|(?-i:\s-[a-zA-Z]*[dFT]\b)))"
    r"|^wget\b.*(?:--post-data|--post-file|--method\s*=\s*(?:POST|PUT))"
    r"|^(?:nc|ncat|scp|rsync|sftp|sendmail|mailx?)\b|^git\s+push\b"
    r"|^(?:npm|pip3?|cargo|gem|go|twine)\s+(?:publish|upload)\b"
    r"|^gh\s+(?:gist\s+create|issue\s+comment|pr\s+create|release\s+upload)\b"
    r"|^aws\s+s3api\s+put-object\b|^(?:xh|https?)\s+(?:POST|PUT|PATCH)\b"
    r"|^(?:invoke-webrequest|invoke-restmethod|iwr|irm)\b.*(?:-method\s+(?:post|put|patch)|-body\b)"
    r"|>\s*/dev/tcp/|^ssh\b.*<", I)
AWS_S3 = re.compile(r"^aws\s+s3\s+(?:cp|sync|mv)\b", I)  # direction is ambiguous
WRITE_CMD = re.compile(
    r"^(?:mkdir|touch|mv|cp|ln|tee|set-content|add-content|out-file|new-item|copy-item|move-item"
    r"|rename-item)\b|^sed\s+-i\b|^git\s+(?:commit|add|checkout|merge|rebase|stash|tag|init|restore"
    r"|switch|mv|pull)\b|^curl\b.*(?:\s-o\s|\s-O\b|--output\b)", I)
TEXT_CMDS = {"echo", "printf", "grep", "egrep", "fgrep", "rg", "ag", "select-string"}  # quoted words are data
NOOP_CMD = re.compile(r"^(?:echo|printf|true|false|:|sleep)(?:\s|$)", I)  # produce output only
INSTALL_CMD = re.compile(r"^(?:npm|pip3?|cargo|yarn|pnpm)\s+(?:install|add|i|update|ci)\b", I)
READ_CMD = re.compile(
    r"^(?:ls|dir|cat|head|tail|less|more|grep|egrep|rg|ag|find|pwd|wc|stat|tree|which"
    r"|where|whoami|date|env|printenv|file|du|df|ps|diff|sort|uniq|cut|cd|test|get-content|get-childitem"
    r"|gc|gci|select-string|test-path|curl|wget)\b|^git\s+(?:status|log|diff|show|fetch|clone|branch"
    r"|ls-files|grep|blame|ls-remote)\b|^npm\s+(?:ls|view|search)\b", I)


def _scan(text: str) -> tuple[list[str], list[str]]:
    """Split a shell string into segments OUTSIDE quotes; drop unquoted '#' comments.

    Returns (segments, command_substitutions). Not a full POSIX parser: it handles quotes,
    backslash escapes, ; & && || | newline, comments and $(...) / `...` substitutions.
    """
    segs: list[str] = []
    subs: list[str] = []
    buf: list[str] = []
    q = None
    i, n = 0, len(text)

    def flush() -> None:
        s = "".join(buf).strip()
        buf.clear()
        if s:
            segs.append(s)

    while i < n:
        c = text[i]
        if q == "'":
            buf.append(c)
            if c == "'":
                q = None
            i += 1
            continue
        if c == "\\" and i + 1 < n:
            buf.append(text[i:i + 2]); i += 2
            continue
        if text.startswith("$(", i):
            depth, j = 1, i + 2
            while j < n and depth:
                depth += (text[j] == "(") - (text[j] == ")")
                j += 1
            subs.append(text[i + 2:j - 1 if depth == 0 else j])
            buf.append(text[i:j]); i = j
            continue
        if c == "`":
            j = text.find("`", i + 1)
            j = n if j < 0 else j
            subs.append(text[i + 1:j]); buf.append(text[i:j + 1]); i = j + 1
            continue
        if q == '"':
            buf.append(c)
            if c == '"':
                q = None
            i += 1
            continue
        if c in "'\"":
            q = c; buf.append(c); i += 1
            continue
        if c == "#" and (not buf or buf[-1].isspace()):
            j = text.find("\n", i)
            i = n if j < 0 else j
            continue
        if c in ";\n":
            flush(); i += 1
        elif c == "|":
            flush(); i += 2 if text.startswith("||", i) else 1
        elif c == "&" and text.startswith("&&", i):
            flush(); i += 2
        elif c == "&" and not (buf and buf[-1] in "<>") and not text.startswith("&>", i):
            flush(); i += 1  # background job
        else:
            buf.append(c); i += 1
    flush()
    return segs, subs


def _mask(s: str) -> str:
    """Replace the contents of quoted strings with '_' so words inside quotes are never commands."""
    out, q, i = [], None, 0
    while i < len(s):
        c = s[i]
        if q:
            if c == q:
                q = None; out.append(c)
            elif c == "\\" and q == '"' and i + 1 < len(s):
                out.append("__"); i += 1
            else:
                out.append("_")
        else:
            if c in "'\"":
                q = c
            out.append(c)
        i += 1
    return "".join(out)


def _shell(text: str, ev, depth: int = 0) -> int:
    """Emit evidence; return the number of segments no rule recognised."""
    unmatched = 0
    if PIPE_TO_SHELL.search(_mask(text)):
        ev("delete", 0.85, "shell", "pipe to shell (code execution, treated as delete-class)")
    segs, subs = _scan(text)
    if depth < 3:
        for sub in subs:
            unmatched += _shell(sub, ev, depth + 1)
    else:
        unmatched += len(subs)  # substitutions beyond the depth limit were not examined
    for seg in segs:
        seg = ENV_PREFIX.sub("", seg.strip())
        if not seg:
            continue
        nested = NESTED.match(seg)
        if nested and depth < 2:
            unmatched += _shell(nested.group(2), ev, depth + 1)
            continue
        masked = _mask(seg)
        head = re.match(r"(?:sudo\s+)?(\S+)", seg, I)
        text_only = bool(head) and head.group(1).lower() in TEXT_CMDS
        rest = re.sub(r"^sudo\s+", "", masked if text_only else seg, flags=I)
        strong = False
        if rest != (masked if text_only else seg):
            ev("change_permissions", 0.85, "shell", "sudo")  # privilege escalation; the command itself is judged below
        for cat, rx, w, why in (("delete", DELETE_CMD, 0.85, "destructive command"),
                                ("change_permissions", PERM_CMD, 0.85, "permission command"),
                                ("send_data", SEND_CMD, 0.85, "outbound data command"),
                                ("write", WRITE_CMD, 0.85, "file/repo write command")):
            if rx.search(rest):
                ev(cat, w, "shell", why); strong = True
        if AWS_S3.search(rest):
            ev("send_data", 0.6, "shell", "aws s3 copy (direction ambiguous)"); strong = True
        if INSTALL_CMD.search(rest):
            ev("write", 0.6, "shell", "package install writes to disk"); strong = True
        redirect = bool(REDIRECT.search(NOISE_REDIRECT.sub(" ", masked)))
        if redirect:
            ev("write", 0.85, "shell", "output redirection")
        reads = bool(READ_CMD.search(rest)) and not strong
        if reads:
            ev("read", 0.8, "shell", "read-only command")
        if not (strong or redirect or reads):
            if NOOP_CMD.search(rest) and not UNSUPPORTED_SYNTAX.search(NOISE_REDIRECT.sub(" ", masked)):
                ev.noop.append(seg)  # recognised, proven to have no effect
            else:
                unmatched += 1
    return unmatched

# ---------------------------------------------------------------- argument rules
RECIPIENT_KEYS = set("to cc bcc recipient recipients email emails address channel chat_id phone".split())
CONTENT_KEYS = set("body message text content subject html attachment attachments data payload json form".split())
URL_KEYS = set("url uri endpoint webhook webhook_url href host".split())
PATH_KEYS = set("path file filename file_path filepath directory dir src dest destination".split())
EDIT_KEYS = set("content text data contents lines new_string old_string patch".split())
PERM_KEYS = set("permission permissions access_level role roles acl privilege privileges grant owner group".split())
ACTION_KEYS = {"action", "operation", "op", "verb"}
DATA_KEYS = CONTENT_KEYS | EDIT_KEYS
ATTACH_PATH = re.compile(r"attachments?_(?:path|paths|file|files)")
MODE_KEYS = {"mode", "method"}  # may also carry an action word (e.g. mode="purge")
MODE_OCTAL = re.compile(r"^[0-7]{3,4}$|^[ugoa]*[+\-=][rwxXst]+$")
MODE_WORDS = {"private", "public", "shared", "readonly", "read-only", "restricted", "world-readable"}
# Name tokens that signal effects hidden behind another component (no shell text to inspect).
OPAQUE_TOKENS = set("callback hook plugin invoke exec execute eval macro handler".split())


class _Walk:
    def __init__(self) -> None:
        self.keys: set[str] = set()
        self.leaves: list[tuple[str, str]] = []
        self.scalars: dict[str, Any] = {}
        self.truncated = False
        self.unmatched = 0
        self.children: list[_Walk] = []  # independent workflow steps, classified separately

    def go(self, obj: Any, key: str = "", depth: int = 0) -> None:
        if depth > MAX_DEPTH:
            self.truncated = True
        elif isinstance(obj, dict):
            for k, v in obj.items():
                self.keys.add(str(k).lower())
                if str(k).lower() in DATA_KEYS and isinstance(v, (dict, list, tuple)):
                    continue  # structured payload/content is data, not a nested call
                self.go(v, str(k).lower(), depth + 1)
        elif isinstance(obj, (list, tuple)):
            if obj and all(isinstance(v, dict) and {str(k).lower() for k in v} & ACTION_KEYS for v in obj):
                for v in obj:  # a list of steps: each step is classified in its own context
                    child = _Walk()
                    child.go(v, key, depth + 1)
                    self.children.append(child)
            else:
                for v in obj:
                    self.go(v, key, depth + 1)
        elif isinstance(obj, str):
            if len(self.leaves) >= MAX_LEAVES:
                self.truncated = True
                return
            if len(obj) > MAX_LEAF_CHARS:
                self.truncated, obj = True, obj[:MAX_LEAF_CHARS]
            self.leaves.append((key, obj))
        else:
            self.scalars.setdefault(key, obj)


def _tokens(text: str) -> list[str]:
    text = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1 \2", text)
    text = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", text)
    return [t for t in re.split(r"[^A-Za-z0-9]+", text.lower()) if t]


def _name_evidence(tool_name: str, ev) -> None:
    if tool_name in BUILTIN:
        ev(BUILTIN[tool_name], 0.95, "name", f"known built-in tool {tool_name}")
        return
    last = tool_name.split("__")[-1]
    toks = _tokens(last)
    verbs = [t for t in toks if t in VERBS]
    perm_noun = any(t in PERM_NOUNS for t in toks)
    for t in verbs:
        cat, w = VERBS[t]
        if perm_noun and (t in GENERIC_WRITE or t in DELETE_VERBS):
            continue  # retargeted below
        ev(cat, w, "name", f"name token '{t}'")
    if perm_noun:
        if any(t in GENERIC_WRITE or t in DELETE_VERBS for t in toks):
            ev("change_permissions", 0.75, "name", "permission noun with a mutation verb")
        elif not verbs:
            ev("change_permissions", 0.55, "name", "permission noun")
    elif not verbs and any(t in SEND_NOUNS for t in toks):
        ev("send_data", 0.5, "name", "messaging noun without a verb")


def _arg_evidence(w: _Walk, ev) -> None:
    keys, sc = w.keys, w.scalars
    if keys & RECIPIENT_KEYS and keys & CONTENT_KEYS:
        ev("send_data", 0.7, "args", "recipient plus content arguments")
    method = str(sc.get("method", "")).upper()
    if keys & URL_KEYS:
        if keys & CONTENT_KEYS or method in {"POST", "PUT", "PATCH"}:
            ev("send_data", 0.75, "args", "URL with body or write method")
        elif method == "DELETE":
            ev("delete", 0.7, "args", "HTTP DELETE")
        else:
            ev("read", 0.55, "args", "URL without a body")
    if keys & PATH_KEYS and keys & EDIT_KEYS:
        ev("write", 0.7, "args", "path plus content arguments")
    if keys & PERM_KEYS:
        ev("change_permissions", 0.65, "args", "permission/role argument")
    mode = sc.get("mode")
    for k, v in w.leaves:
        if k == "mode":
            mode = v
    if isinstance(mode, str):
        if MODE_OCTAL.match(mode):
            ev("change_permissions", 0.85, "args", "mode looks like chmod value")
        elif mode.lower() in MODE_WORDS:
            ev("change_permissions", 0.7, "args", "mode is an access level")
        elif mode in {"r", "rb"}:
            ev("read", 0.6, "args", "file mode read")
        elif mode in {"w", "wb", "a", "ab", "x", "w+", "a+"}:
            ev("write", 0.6, "args", "file mode write")
    for k, v in w.leaves:
        if k in ACTION_KEYS | MODE_KEYS:
            found = False
            for t in _tokens(v):
                if t in VERBS:
                    found = True
                    ev(VERBS[t][0], 0.65, "args", f"{k}='{t}'")
            if k in ACTION_KEYS and not found:
                w.unmatched += 1  # explicit action value we do not understand
    if any(ATTACH_PATH.fullmatch(k) for k in keys):
        ev("read", 0.7, "args", "local file attachment path")
    shell_keys = keys & SHELL_KEYS
    if shell_keys:
        text = " ".join(v for k, v in w.leaves if k in shell_keys)
        w.unmatched += _shell(text, ev)
    for child in w.children:
        _arg_evidence(child, ev)
        w.unmatched += child.unmatched
        w.truncated = w.truncated or child.truncated


def _schema_evidence(schema: Any, ev) -> None:
    props: set[str] = set()
    if isinstance(schema, dict):
        inner = schema.get("inputSchema") or schema.get("input_schema") or schema
        p = inner.get("properties") if isinstance(inner, dict) else None
        if isinstance(p, dict):
            props = {str(k).lower() for k in list(p)[:100]}
    if props & RECIPIENT_KEYS and props & CONTENT_KEYS:
        ev("send_data", 0.25, "schema", "schema has recipient and content")
    if props & URL_KEYS and props & CONTENT_KEYS:
        ev("send_data", 0.25, "schema", "schema has URL and body")
    if props & PERM_KEYS or "mode" in props:
        ev("change_permissions", 0.25, "schema", "schema has permission fields")
    if props & PATH_KEYS and props & EDIT_KEYS:
        ev("write", 0.25, "schema", "schema has path and content")


RO_CLAIM = re.compile(r"\b(?:read[- ]?only|only reads?|does not (?:modify|write|delete|send|change)"
                      r"|no side[- ]effects?|harmless|safe|just (?:reads?|views?|lists?))\b", I)
INJECT = re.compile(r"ignore (?:all |any |previous |prior |the )*(?:security|instructions?|checks?|polic(?:y|ies)|rules?)"
                    r"|do not (?:ask|warn|confirm)|(?:already|pre-?)approved|bypass|disable (?:security|checks)"
                    r"|you must (?:call|run|send)|system prompt", I)


def _canon(obj: Any) -> str:
    try:
        return json.dumps(obj, sort_keys=True, default=str)
    except (TypeError, ValueError):
        return repr(obj)


def _error(reason: str) -> dict[str, Any]:
    return {"status": "error", "actions": [], "unknown": True, "confidence": 0.0, "uncertainty": 1.0,
            "reason_codes": ["invalid_input"], "reason": reason, "scores": {},
            "description_conflict": False, "description_suspicious": False,
            "name_conflict": False, "schema_mismatch": False, "truncated": False}


def classify(event: Any) -> dict[str, Any]:
    if not isinstance(event, dict):
        return _error("invalid_input: event must be an object")
    name = event.get("tool_name")
    if not isinstance(name, str) or not name.strip():
        return _error("invalid_input: tool_name must be a non-empty string")
    args = event.get("raw_arguments")
    if isinstance(args, str):
        try:
            args = json.loads(args)
        except ValueError:
            pass  # keep as a raw string leaf
    if args is not None and not isinstance(args, (dict, list, str, int, float, bool)):
        return _error("invalid_input: raw_arguments is not JSON-like")

    evid: dict[str, list[tuple[float, str, str]]] = {}

    def ev(cat: str, w: float, src: str, detail: str) -> None:
        evid.setdefault(cat, []).append((w, src, detail))

    ev.noop = []  # shell segments proven to have no effect (D07)
    walk = _Walk()
    walk.go(args)
    if isinstance(args, str):
        walk.leaves.append(("", args[:MAX_LEAF_CHARS]))
    _name_evidence(name, ev)
    name_cats = {c for c, items in evid.items() if any(s == "name" for _, s, _ in items)}
    before = {c: len(v) for c, v in evid.items()}
    _arg_evidence(walk, ev)
    if set(_tokens(name.split("__")[-1])) & SHELL_TOKENS and not (walk.keys & SHELL_KEYS):
        walk.unmatched += _shell(" ".join(v for _, v in walk.leaves), ev)
    if set(_tokens(name.split("__")[-1])) & OPAQUE_TOKENS and not (walk.keys & SHELL_KEYS):
        walk.unmatched += 1  # effects hidden behind a callback/plugin: partial unknown
    arg_cats = {c for c, items in evid.items() if any(s in ("args", "shell") for _, s, _ in items)}
    declared, pinned = event.get("tool_schema"), event.get("pinned_schema")
    mismatch = pinned is not None and declared is not None and _canon(declared) != _canon(pinned)
    _schema_evidence(pinned if pinned is not None else declared, ev)

    name_conflict = name_cats == {"read"} and bool(arg_cats & {"write", "delete", "send_data", "change_permissions"})
    if name_conflict:  # a read-like name does not prove read-only: drop name-only read evidence
        evid["read"] = [i for i in evid["read"] if i[1] != "name"]
        if not evid["read"]:
            del evid["read"]
    scores: dict[str, float] = {}
    for cat, items in evid.items():
        p = 1.0
        for w, _, _ in items:
            p *= 1 - w
        scores[cat] = round(min(1 - p, 0.99), 2)
    included = [c for c in CATEGORIES if scores.get(c, 0) >= THRESHOLD]

    desc = event.get("tool_description")
    desc = desc[:MAX_DESC_CHARS] if isinstance(desc, str) else ""
    risky = {"write", "delete", "send_data", "change_permissions"}
    flags = {
        "description_conflict": bool(RO_CLAIM.search(desc)) and bool(set(included) & risky),
        "description_suspicious": bool(INJECT.search(desc)),
        "name_conflict": name_conflict,
        "schema_mismatch": mismatch,
        "truncated": walk.truncated,
    }
    out: dict[str, Any] = dict(flags)
    if not included and ev.noop and walk.unmatched == 0 and not walk.truncated:
        # D07: every examined command is a proven no-op -> no actions, nothing unknown
        out.update(status="ok", actions=[], unknown=False, confidence=0.9, uncertainty=0.1,
                   reason_codes=["proven_noop"] + [k for k, v in flags.items() if v],
                   reason="all commands are proven no-ops (echo/printf/true/false/:/sleep)", scores=scores)
        return out
    if not included:
        out.update(status="unknown", actions=[], unknown=True, confidence=0.0, uncertainty=1.0,
                   reason_codes=["no_rule_matched"] + [k for k, v in flags.items() if v],
                   reason="no rule matched; weak signals: " + (", ".join(f"{c}={s}" for c, s in scores.items()) or "none"),
                   scores=scores)
        return out
    confidence = min(scores[c] for c in included)
    if walk.truncated:
        confidence = min(confidence, 0.2)
    if mismatch:
        confidence = min(confidence, 0.5)
    partial = walk.unmatched > 0 or walk.truncated  # unexamined input = effects not fully known
    if partial:
        confidence = min(confidence, 0.5)
    top = sorted((i for c in included for i in evid[c]), reverse=True)[:3]
    codes = sorted({f"{src}:{c}" for c in included for _, src, _ in evid[c]},
                   key=lambda x: (x.split(":")[1], x))
    out.update(status="ok", actions=included, unknown=partial, confidence=round(confidence, 2),
               uncertainty=round(1 - confidence, 2),
               reason_codes=codes + (["partial_unknown"] if partial else []) + [k for k, v in flags.items() if v and k not in ("name_conflict",)] +
               (["name_conflict"] if flags["name_conflict"] else []),
               reason="; ".join(f"{s}: {d}" for _, s, d in top) + ("; input truncated" if walk.truncated else ""),
               scores=scores)
    return out


def main() -> int:
    for line in sys.stdin:
        if line.strip():
            try:
                result = classify(json.loads(line))
            except ValueError:
                result = _error("invalid_input: not valid JSON")
            print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())