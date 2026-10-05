#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Opt-in populated restore on a disposable literal-loopback PostgreSQL instance.

Creates fresh databases and a fixture role, never starts a server or delivery worker,
and retains all credentials/snapshots below ignored target in an owner-only directory.
Windows secret artifacts fail closed. The default command launches no tools.
"""

import argparse
from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import subprocess
import sys
from urllib.parse import parse_qsl, quote, unquote, urlsplit


DATABASE_ENV = "LLM_FW_RESTORE_FIXTURE_DATABASE_URL"
TARGET_ENV = "LLM_FW_RESTORE_FIXTURE_RESTORED_DATABASE_FINGERPRINT"
IDENTITY_SQL = ("SELECT current_database() || '|' || "
    "COALESCE(host(inet_server_addr()), 'local') || '|' || "
    "COALESCE(inet_server_port()::text, 'local');")
MAX_OUTPUT = 16 * 1024 * 1024
NAME = re.compile(r"[a-z_][a-z0-9_]{0,62}\Z")
COMMON_RESULT = {
    "schema_version": 1, "status": "passed", "tenants": 2,
    "service_accounts": 2, "webhook_destinations": 1, "pending_deliveries": 1,
    "security_events": 2, "retained_token_authenticated": True,
    "revoked_token_rejected": True, "tenant_isolation_verified": True,
    "destination_active": True, "model_requests_sent": 0, "webhook_requests_sent": 0,
}


class AcceptanceError(Exception):
    """Messages are fixed, public-safe descriptions; never interpolate inputs."""


@dataclass(frozen=True)
class Endpoint:
    host: str
    port: int
    user: str
    password: str
    database: str

    def url(self):
        host = f"[{self.host}]" if ":" in self.host else self.host
        return (f"postgresql://{quote(self.user, safe='')}:{quote(self.password, safe='')}"
                f"@{host}:{self.port}/{quote(self.database, safe='')}?sslmode=disable")

    def environment(self):
        return {"PGHOST": self.host, "PGPORT": str(self.port), "PGUSER": self.user,
                "PGPASSWORD": self.password, "PGDATABASE": self.database,
                "PGSSLMODE": "disable", "PGCONNECT_TIMEOUT": "10"}


def parse_admin_url(value):
    try:
        parsed = urlsplit(value)
        endpoint = Endpoint(parsed.hostname, parsed.port, unquote(parsed.username or ""),
                            unquote(parsed.password or ""), unquote(parsed.path[1:]))
        valid = (parsed.scheme in {"postgres", "postgresql"}
                 and parsed.hostname in {"127.0.0.1", "::1"}
                 and parsed.port is not None and 1 <= parsed.port <= 65535
                 and not parsed.fragment and parsed.path.startswith("/")
                 and parse_qsl(parsed.query, strict_parsing=True) == [("sslmode", "disable")]
                 and endpoint.user and endpoint.password and NAME.fullmatch(endpoint.database)
                 and all(c not in endpoint.user + endpoint.password for c in "\x00\r\n"))
    except (TypeError, ValueError):
        valid = False
    if not valid:
        raise AcceptanceError("A literal-loopback disposable PostgreSQL admin URL is required.")
    return endpoint


def child_environment(overrides):
    # Do not inherit libpq routing/options, provider credentials, dotenv paths,
    # proxy configuration or verbose tracing from the operator's environment.
    allowed = {"PATH", "SYSTEMROOT", "WINDIR", "HOME", "TMPDIR", "TMP", "TEMP",
               "LANG", "LC_ALL", "LD_LIBRARY_PATH", "DYLD_LIBRARY_PATH"}
    result = {key: value for key, value in os.environ.items() if key.upper() in allowed}
    result.update(overrides)
    return result


def checked(argv, *, env, cwd, input_text=None):
    if not isinstance(argv, list) or not argv or any(not isinstance(x, str) or "\x00" in x for x in argv):
        raise AcceptanceError("Invalid tool invocation.")
    try:
        result = subprocess.run(argv, env=env, cwd=cwd, input=input_text,
            capture_output=True, text=True, check=True, timeout=300)
        if len(result.stdout) > MAX_OUTPUT or len(result.stderr) > MAX_OUTPUT:
            raise AcceptanceError("Tool output exceeded the fixture limit.")
        return result.stdout
    except (OSError, subprocess.SubprocessError, UnicodeError):
        raise AcceptanceError("An acceptance tool failed; private output was withheld.") from None


def private_run_directory(workspace):
    if os.name != "posix":
        raise AcceptanceError("Secret artifacts require Unix owner-only permissions.")
    workspace = Path(workspace).absolute()
    if workspace.resolve() != workspace:
        raise AcceptanceError("Private artifact paths must not be redirected.")
    target = workspace / "target"
    if target.is_symlink() or target.resolve() != target.absolute():
        raise AcceptanceError("Private artifact paths must not be redirected.")
    target.mkdir(exist_ok=True)
    run = target / ("populated-restore-" + secrets.token_hex(16))
    try:
        run.mkdir(mode=0o700)
    except OSError:
        raise AcceptanceError("Could not reserve a fresh private run directory.") from None
    if (run.stat().st_uid != os.geteuid() or stat.S_IMODE(run.stat().st_mode) != 0o700
            or run.resolve() != run.absolute()):
        raise AcceptanceError("Private run directory permissions are unsafe.")
    return run


def private_json(path, value):
    if os.name != "posix":
        raise AcceptanceError("Secret artifacts require Unix owner-only permissions.")
    path = Path(path)
    parent = path.parent
    if (parent.resolve() != parent.absolute() or parent.stat().st_uid != os.geteuid()
            or stat.S_IMODE(parent.stat().st_mode) != 0o700):
        raise AcceptanceError("Private artifact parent permissions are unsafe.")
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
    except OSError:
        raise AcceptanceError("Could not create an exclusive private artifact.") from None


def strict_json(text):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate key")
            result[key] = value
        return result
    try:
        return json.loads(text, object_pairs_hook=pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(ValueError("constant")))
    except (ValueError, TypeError, RecursionError):
        raise AcceptanceError("An acceptance tool returned invalid structured output.") from None


def helper_result(text, mode):
    expected = dict(COMMON_RESULT, mode=mode)
    if mode == "exercise-restored":
        expected.update(pending_deliveries=2, security_events=4,
            retained_token_authenticated=False, destination_active=False,
            restored_only_mutation=True, retained_token_revoked=True,
            new_delivery_enqueued=True, deactivated_destination_suppressed_delivery=True)
    elif mode not in {"seed", "probe"}:
        raise AcceptanceError("Invalid fixture phase.")
    result = strict_json(text)
    # Type checks matter: Python otherwise treats 1 as equal to True.
    if (not isinstance(result, dict) or result.keys() != expected.keys()
            or any(type(result[key]) is not type(value) or result[key] != value
                   for key, value in expected.items())):
        raise AcceptanceError("Fixture verification failed or returned unexpected fields.")
    return result


def canonical_state(value):
    # JSON booleans and numeric values must remain distinct during equality.
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def acceptance_flow(backend):
    """Exercise only after equality and fresh identity checks; keep source immutable."""
    backend.prepare()
    identities = backend.identities()
    if identities[0] == identities[1]:
        raise AcceptanceError("Source and drill resolve to the same database.")
    backend.migrate()
    backend.helper("seed", "source")
    backend.helper("probe", "source")
    source = backend.snapshot("source", "source-before")
    source_state = canonical_state(source)
    backend.restore()
    if backend.identities() != identities:
        raise AcceptanceError("Database identity changed during the restore.")
    backend.helper("probe", "drill")
    restored = backend.snapshot("drill", "restored-before")
    restored_state = canonical_state(restored)
    if source_state != restored_state:
        raise AcceptanceError("Complete source and restored state differ.")
    if canonical_state(backend.snapshot("source", "source-before-exercise")) != source_state:
        raise AcceptanceError("Source state changed during the restore.")
    if backend.identities() != identities:
        raise AcceptanceError("Database identity changed before the restored exercise.")
    try:
        backend.helper("exercise-restored", "drill", identities[1])
    finally:
        # Even a partially failed exercise must verify the source was untouched.
        if backend.identities() != identities:
            raise AcceptanceError("Database identity changed during the restored exercise.")
        backend.helper("probe", "source")
        if canonical_state(backend.snapshot("source", "source-after")) != source_state:
            raise AcceptanceError("Source state changed during the restored exercise.")
    exercised = backend.snapshot("drill", "restored-after")
    if canonical_state(exercised) == restored_state:
        raise AcceptanceError("Restored exercise did not change restored state.")
    return {"schema_version": 1, "status": "passed", "exact_private_state_equal": True,
            "source_unchanged": True, "restored_only_exercise": True,
            "tenants": len(source["tables"]["tenants"]),
            "service_accounts": len(source["tables"]["workspace_service_accounts"]),
            "webhook_destinations": len(source["tables"]["tenant_webhook_destinations"]),
            "pending_deliveries_before": len(source["tables"]["tenant_webhook_deliveries"]),
            "model_requests_sent": 0, "webhook_requests_sent": 0}


class PostgresBackend:
    def __init__(self, workspace, tools, admin, runner=checked):
        self.workspace = Path(workspace).resolve()
        self.tools = tools
        self.admin = admin
        self.runner = runner
        self.run_directory = None
        self.databases = {}

    def invoke(self, argv, overrides=None, input_text=None):
        return self.runner(argv, env=child_environment(overrides or {}),
                           cwd=self.run_directory, input_text=input_text)

    def sql(self, endpoint, query):
        return self.invoke([self.tools["psql"], "--no-psqlrc", "--quiet", "--tuples-only",
                            "--no-align", "--set", "ON_ERROR_STOP=1"],
                           endpoint.environment(), query).strip()

    def prepare(self):
        self.run_directory = private_run_directory(self.workspace)
        nonce = secrets.token_hex(12)
        role, source, drill = ("fw_restore_" + nonce, "fw_restore_source_" + nonce,
                                "fw_restore_drill_" + nonce)
        password = secrets.token_urlsafe(32)
        self.databases = {name: Endpoint(self.admin.host, self.admin.port, role, password, database)
                          for name, database in [("source", source), ("drill", drill)]}
        private_json(self.run_directory / "credentials.json",
            {"schema_version": 1, "source_url": self.databases["source"].url(),
             "drill_url": self.databases["drill"].url()})
        # Reserve a marker before any DB mutation. Failure/partial runs are kept,
        # and never resumed or cleaned up automatically.
        private_json(self.run_directory / "run-start.json", {"schema_version": 1})
        collision = self.sql(self.admin, f"SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='{role}') "
            f"OR EXISTS(SELECT 1 FROM pg_database WHERE datname IN ('{source}','{drill}'));")
        if collision != "f":
            raise AcceptanceError("Fresh fixture database or role reservation collided.")
        self.sql(self.admin, f"CREATE ROLE {role} LOGIN PASSWORD '{password}' "
                 "NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION;")
        self.sql(self.admin, f"CREATE DATABASE {source} OWNER {role} TEMPLATE template0;")
        self.sql(self.admin, f"CREATE DATABASE {drill} OWNER {role} TEMPLATE template0;")
        identity = self.run_directory / "backup-identity.age"
        self.invoke([self.tools["age-keygen"], "-o", str(identity)])
        if (identity.is_symlink() or not identity.is_file() or identity.stat().st_uid != os.geteuid()
                or stat.S_IMODE(identity.stat().st_mode) & 0o077):
            raise AcceptanceError("Backup identity permissions are unsafe.")
        recipient = self.invoke([self.tools["age-keygen"], "-y", str(identity)]).strip()
        if not re.fullmatch(r"age1[0-9a-z]{58}", recipient):
            raise AcceptanceError("Invalid backup recipient output.")
        self.recipient = recipient
        self.identity_path = identity
        (self.run_directory / "firewall.yaml").write_text(
            "bind: '127.0.0.1:0'\nupstream: {}\ntenant_store:\n  enabled: true\n"
            "  backend: postgres\n  postgres_url_env: LLM_FW_RESTORE_FIXTURE_DATABASE_URL\n",
            encoding="utf-8")
        os.chmod(self.run_directory / "firewall.yaml", 0o600)

    def identities(self):
        result = tuple(self.sql(self.databases[name], IDENTITY_SQL) for name in ("source", "drill"))
        for name, fingerprint in zip(("source", "drill"), result):
            endpoint = self.databases[name]
            if fingerprint != f"{endpoint.database}|{endpoint.host}|{endpoint.port}":
                raise AcceptanceError("Database fingerprint did not match the reserved endpoint.")
        return result

    def migrate(self):
        self.invoke([self.tools["gateway"], "migrate"],
                    {DATABASE_ENV: self.databases["source"].url()})

    def helper(self, mode, database, expected_fingerprint=None):
        if (mode not in {"seed", "probe", "exercise-restored"}
                or database not in {"source", "drill"}
                or (mode == "seed" and database != "source")
                or (mode == "exercise-restored" and (database != "drill" or not expected_fingerprint))):
            raise AcceptanceError("Invalid fixture database for phase.")
        env = {DATABASE_ENV: self.databases[database].url()}
        if expected_fingerprint is not None:
            env[TARGET_ENV] = expected_fingerprint
        result = helper_result(self.invoke([self.tools["helper"], mode, str(self.run_directory)], env), mode)
        return result

    def snapshot(self, database, name):
        endpoint = self.databases[database]
        catalog = strict_json(self.sql(endpoint, "BEGIN READ ONLY; SELECT json_build_object("
            "'tables',(SELECT COALESCE(json_agg(tablename ORDER BY tablename),'[]'::json) FROM pg_tables "
            "WHERE schemaname='public'),'sequences',(SELECT COALESCE(json_agg(sequencename ORDER BY "
            "sequencename),'[]'::json) FROM pg_sequences WHERE schemaname='public')); COMMIT;"))
        if (not isinstance(catalog, dict) or set(catalog) != {"tables", "sequences"}
                or any(not isinstance(values, list) or len(values) > 100
                       or any(not isinstance(value, str) or not NAME.fullmatch(value) for value in values)
                       or len(set(values)) != len(values) for values in catalog.values())
                or not catalog["tables"]):
            raise AcceptanceError("Fixture snapshot catalog is invalid.")
        def map_sql(names, sequence=False):
            if not names:
                return "'{}'::jsonb"
            entries = []
            for table in names:
                if sequence:
                    value = f"(SELECT jsonb_build_object('last_value',last_value,'is_called',is_called) FROM public.{table})"
                else:
                    value = f"(SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text),'[]'::jsonb) FROM public.{table} t)"
                entries.append(f"SELECT '{table}'::text AS name, {value} AS value")
            return "(SELECT jsonb_object_agg(name,value) FROM (" + " UNION ALL ".join(entries) + ") entries)"
        query = ("BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY; SET LOCAL TIME ZONE 'UTC'; "
                 "SELECT jsonb_build_object('tables'," + map_sql(catalog["tables"]) +
                 ",'sequences'," + map_sql(catalog["sequences"], True) + "); COMMIT;")
        result = strict_json(self.sql(endpoint, query))
        if (not isinstance(result, dict) or set(result) != {"tables", "sequences"}
                or not isinstance(result["tables"], dict) or not isinstance(result["sequences"], dict)
                or set(result["tables"]) != set(catalog["tables"])
                or set(result["sequences"]) != set(catalog["sequences"])
                or any(not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows)
                       for rows in result["tables"].values())
                or any(not isinstance(value, dict) or set(value) != {"last_value", "is_called"}
                       or type(value["last_value"]) is not int or type(value["is_called"]) is not bool
                       for value in result["sequences"].values())):
            raise AcceptanceError("Fixture snapshot is invalid.")
        private_json(self.run_directory / (name + ".json"), result)
        return result

    def restore(self):
        # Reuse the original encrypted restore with explicit, checked arguments.
        # Captured stdout/stderr are never copied into the public report.
        env = {"DOTNET_SYSTEM_GLOBALIZATION_INVARIANT": "1",
               "PATH": os.pathsep.join(dict.fromkeys([
            str(Path(self.tools[tool]).parent) for tool in ("pg_dump", "pg_restore", "psql", "age")]
            + [os.environ.get("PATH", "")]))}
        self.invoke([self.tools["pwsh"], "-NoProfile", "-NonInteractive", "-File",
            str(self.workspace / "scripts" / "postgres-restore-drill.ps1"),
            "-SourceDatabaseUrl", self.databases["source"].url(),
            "-DrillDatabaseUrl", self.databases["drill"].url(),
            "-BackupRecipient", self.recipient, "-BackupIdentity", str(self.identity_path),
            "-BackupPath", str(self.run_directory / "control-plane.dump.age"),
            "-MinimumSchemaVersion", "25"], env)


def tool_path(value):
    path = shutil.which(value)
    if path is None:
        raise AcceptanceError("A required acceptance tool is unavailable.")
    return str(Path(path).resolve())


def execute(args):
    if os.name != "posix":
        raise AcceptanceError("Secret artifacts require Unix owner-only permissions.")
    if not args.helper or not args.gateway:
        raise AcceptanceError("Explicit built helper and gateway paths are required.")
    admin = parse_admin_url(os.environ.get(args.admin_url_env, ""))
    tools = {name: tool_path(getattr(args, name)) for name in
             ("helper", "gateway", "psql", "pwsh", "age", "age_keygen", "pg_dump", "pg_restore")}
    tools["age-keygen"] = tools.pop("age_keygen")
    workspace = Path(__file__).resolve().parents[1]
    backend = PostgresBackend(workspace, tools, admin)
    report = acceptance_flow(backend)
    private_json(backend.run_directory / "evidence.json", report)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true", help="allocate fresh fixtures on an explicitly disposable PG instance")
    parser.add_argument("--admin-url-env", default="LLM_FW_RESTORE_FIXTURE_ADMIN_URL")
    parser.add_argument("--helper")
    parser.add_argument("--gateway")
    for name in ("psql", "pwsh", "age", "age-keygen", "pg-dump", "pg-restore"):
        parser.add_argument("--" + name, default=name.replace("-", "_") if name in {"pg-dump", "pg-restore"} else name)
    args = parser.parse_args(argv)
    if not args.run:
        print(json.dumps({"schema_version": 1, "status": "not_run", "processes_started": 0}))
        return 0
    try:
        report = execute(args)
    except AcceptanceError as error:
        print(json.dumps({"schema_version": 1, "status": "failed", "reason": str(error)}))
        return 1
    except (OSError, ValueError, KeyError, TypeError):
        print(json.dumps({"schema_version": 1, "status": "failed", "reason": "Acceptance failed; private details were withheld."}))
        return 1
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
