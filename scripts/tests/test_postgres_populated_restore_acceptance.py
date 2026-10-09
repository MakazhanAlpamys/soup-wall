# SPDX-License-Identifier: Apache-2.0
"""Local orchestration checks; no PostgreSQL, providers or services launched."""
import copy
from contextlib import redirect_stdout
import importlib.util
import io
import ipaddress
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / "postgres-populated-restore-acceptance.py"
SPEC = importlib.util.spec_from_file_location("populated_restore_under_test", SCRIPT)
RESTORE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = RESTORE
SPEC.loader.exec_module(RESTORE)

# macOS places the default temp directory under the /var -> /private/var
# symlink, which the private-directory guards correctly refuse.
RESOLVED_TEMPDIR = patch.object(tempfile, "tempdir", os.path.realpath(tempfile.gettempdir()))


def setUpModule():
    RESOLVED_TEMPDIR.start()


def tearDownModule():
    RESOLVED_TEMPDIR.stop()


def reserve_fixture_tmp(parent):
    # Parsing/ordering cases are portable; Unix permission behavior is exercised
    # separately against the real directory guard and an actual child process.
    child = Path(parent) / "tmp"
    child.mkdir(mode=0o700)
    return child


class FakeBackend:
    def __init__(self):
        self.calls = []
        self.source = {"tables": {"tenants": [{"id": "synthetic-tenant"}],
            "workspace_service_accounts": [{"token_hash": "private-fixture-hash"}],
            "tenant_webhook_destinations": [{}], "tenant_webhook_deliveries": [{}]},
            "sequences": {}}
        self.restored = copy.deepcopy(self.source)
        self.drift = False
        self.changed_source = False
        self.changed_identity = False
        self.exercised = False

    def prepare(self):
        self.calls.append("prepare")

    def identities(self):
        self.calls.append("identities")
        return ("source|127.0.0.1|5432", "source|127.0.0.1|5432" if
                self.changed_identity else "drill|127.0.0.1|5432")

    def migrate(self):
        self.calls.append("migrate-source")

    def helper(self, mode, database, expected_fingerprint=None):
        self.calls.append((mode, database, expected_fingerprint))
        if mode == "exercise-restored":
            self.exercised = True
            self.restored["tables"]["tenant_webhook_deliveries"].append({"new": True})
            if self.changed_source:
                self.source["tables"]["tenants"][0]["private"] = "must-not-publish"
        return {}

    def snapshot(self, database, name):
        self.calls.append(("snapshot", database, name))
        state = copy.deepcopy(self.source if database == "source" else self.restored)
        if self.drift and database == "drill":
            state["tables"]["workspace_service_accounts"][0]["token_hash"] = "different-private-hash"
        return state

    def restore(self):
        self.calls.append("encrypted-restore")


class RestoreOrdering(unittest.TestCase):
    def test_full_equality_precedes_target_bound_exercise_and_source_recheck(self):
        backend = FakeBackend()
        report = RESTORE.acceptance_flow(backend)
        exercise = ("exercise-restored", "drill", "drill|127.0.0.1|5432")
        self.assertLess(backend.calls.index(("snapshot", "drill", "restored-before")),
                        backend.calls.index(exercise))
        self.assertLess(backend.calls.index("encrypted-restore"), backend.calls.index(exercise))
        self.assertGreater(backend.calls.index(("snapshot", "source", "source-after")),
                           backend.calls.index(exercise))
        self.assertEqual([x for x in backend.calls if isinstance(x, tuple) and x[0] ==
                          "exercise-restored"], [exercise])
        self.assertTrue(report["exact_private_state_equal"])
        self.assertTrue(report["source_unchanged"])
        self.assertNotIn("private-fixture-hash", json.dumps(report))
        self.assertNotIn("synthetic-tenant", json.dumps(report))

    def test_private_field_drift_refuses_exercise_without_exposing_difference(self):
        backend = FakeBackend()
        backend.drift = True
        with self.assertRaises(RESTORE.AcceptanceError) as error:
            RESTORE.acceptance_flow(backend)
        self.assertFalse(backend.exercised)
        self.assertNotIn("private", str(error.exception))
        self.assertNotIn("hash", str(error.exception))

    def test_source_mutation_is_failure_even_when_restored_exercise_succeeds(self):
        backend = FakeBackend()
        backend.changed_source = True
        with self.assertRaises(RESTORE.AcceptanceError) as error:
            RESTORE.acceptance_flow(backend)
        self.assertTrue(backend.exercised)
        self.assertNotIn("must-not-publish", str(error.exception))

    def test_same_physical_database_refused_before_migration_or_seed(self):
        backend = FakeBackend()
        backend.changed_identity = True
        with self.assertRaises(RESTORE.AcceptanceError):
            RESTORE.acceptance_flow(backend)
        self.assertEqual(backend.calls, ["prepare", "identities"])

    def test_identity_change_after_restore_refuses_exercise(self):
        backend = FakeBackend()
        original = backend.identities
        count = 0
        def identities():
            nonlocal count
            count += 1
            return original() if count == 1 else ("source|127.0.0.1|5432", "other|127.0.0.1|5432")
        backend.identities = identities
        with self.assertRaises(RESTORE.AcceptanceError):
            RESTORE.acceptance_flow(backend)
        self.assertFalse(backend.exercised)

    def test_json_boolean_to_numeric_change_is_not_exact_equality(self):
        backend = FakeBackend()
        backend.source["tables"]["tenant_webhook_destinations"][0]["active"] = True
        backend.restored["tables"]["tenant_webhook_destinations"][0]["active"] = 1
        with self.assertRaises(RESTORE.AcceptanceError):
            RESTORE.acceptance_flow(backend)
        self.assertFalse(backend.exercised)

    def test_source_recheck_also_runs_after_partial_exercise_failure(self):
        backend = FakeBackend()
        original = backend.helper
        def helper(mode, database, expected_fingerprint=None):
            result = original(mode, database, expected_fingerprint)
            if mode == "exercise-restored":
                raise RESTORE.AcceptanceError("Fixture exercise failed.")
            return result
        backend.helper = helper
        with self.assertRaises(RESTORE.AcceptanceError):
            RESTORE.acceptance_flow(backend)
        self.assertIn(("snapshot", "source", "source-after"), backend.calls)


class RestoreRefusals(unittest.TestCase):
    def test_admin_endpoint_requires_numeric_loopback_explicit_port_and_disable_tls(self):
        good = "postgresql://fixture:neutral-secret@127.0.0.1:5432/postgres?sslmode=disable"
        endpoint = RESTORE.parse_admin_url(good)
        self.assertEqual(endpoint.host, "127.0.0.1")
        for value in [good.replace("127.0.0.1", "localhost"),
                      good.replace("127.0.0.1", "203.0.113.1"),
                      good.replace(":5432", ""), good + "&host=203.0.113.1",
                      good + "&options=-c%20search_path=private", good + "#ignored",
                      good.replace("postgresql:", "file:"), good.replace("disable", "prefer")]:
            with self.subTest(value=value):
                with self.assertRaises(RESTORE.AcceptanceError) as error:
                    RESTORE.parse_admin_url(value)
                self.assertNotIn("neutral-secret", str(error.exception))

    def test_database_identity_removes_postgres_inet_cidr_for_ipv4_and_ipv6(self):
        for host, prefix in [("127.0.0.1", 32), ("::1", 128)]:
            with self.subTest(host=host):
                backend = RESTORE.PostgresBackend(Path.cwd(), {}, None)
                backend.server_identity = (host, 5432)
                backend.databases = {name: RESTORE.Endpoint(host, 5432, "fixture", "neutral", name)
                                     for name in ("source", "drill")}
                def postgres_identity(endpoint, query):
                    # PostgreSQL inet::text includes its mask. host(inet) returns
                    # the address alone, which is the literal endpoint identity.
                    address = host if "host(inet_server_addr())" in query else f"{host}/{prefix}"
                    return f"{endpoint.database}|{address}|{endpoint.port}"
                with patch.object(backend, "sql", side_effect=postgres_identity):
                    self.assertEqual(backend.identities(),
                        (f"source|{host}|5432", f"drill|{host}|5432"))

    def test_canonical_host_still_requires_reserved_database_and_port(self):
        backend = RESTORE.PostgresBackend(Path.cwd(), {}, None)
        backend.server_identity = ("127.0.0.1", 5432)
        backend.databases = {name: RESTORE.Endpoint("127.0.0.1", 5432, "fixture", "neutral", name)
                             for name in ("source", "drill")}
        for mismatched in ["other|127.0.0.1|5432", "source|127.0.0.1|5433"]:
            with self.subTest(identity=mismatched), patch.object(backend, "sql", return_value=mismatched):
                with self.assertRaises(RESTORE.AcceptanceError):
                    backend.identities()

    def test_admin_observed_docker_server_supports_mapped_loopback_client_route(self):
        backend = RESTORE.PostgresBackend(Path.cwd(), {}, None)
        backend.server_identity = ("172.18.0.2", 5432)
        backend.databases = {name: RESTORE.Endpoint("127.0.0.1", 6543, "fixture", "neutral", name)
                             for name in ("source", "drill")}
        observed = ("source|172.18.0.2|5432", "drill|172.18.0.2|5432")
        with patch.object(backend, "sql", side_effect=observed):
            try:
                identities = backend.identities()
            except RESTORE.AcceptanceError:
                self.fail("The reserved databases must accept the admin-pinned server behind the client route.")
            self.assertEqual(identities, observed)
        self.assertEqual(backend.server_identity, ("172.18.0.2", 5432))
        self.assertEqual(backend.databases["source"].host, "127.0.0.1")
        self.assertEqual(backend.databases["source"].port, 6543)

    def test_ipv4_mapped_ipv6_numeric_spellings_share_normalized_server_pin(self):
        try:
            dotted = RESTORE.observed_server_identity("postgres|::ffff:172.18.0.2|5432", "postgres")
            hexadecimal = RESTORE.observed_server_identity("postgres|::ffff:ac12:2|5432", "postgres")
        except RESTORE.AcceptanceError:
            self.fail("Both valid numeric IPv4-mapped IPv6 spellings must be accepted.")
        self.assertEqual(dotted, hexadecimal)
        self.assertEqual(dotted[1], 5432)
        self.assertEqual(ipaddress.ip_address(dotted[0]).ipv4_mapped, ipaddress.IPv4Address("172.18.0.2"))

    def test_missing_admin_binding_refuses_before_database_probe(self):
        backend = RESTORE.PostgresBackend(Path.cwd(), {}, None)
        backend.databases = {name: RESTORE.Endpoint("127.0.0.1", 5432, "fixture", "neutral", name)
                             for name in ("source", "drill")}
        with patch.object(backend, "sql", side_effect=("source|127.0.0.1|5432", "drill|127.0.0.1|5432")) as sql:
            with self.assertRaises(RESTORE.AcceptanceError):
                backend.identities()
        sql.assert_not_called()

    def test_reserved_databases_must_share_pinned_server_and_port(self):
        backend = RESTORE.PostgresBackend(Path.cwd(), {}, None)
        backend.server_identity = ("172.18.0.2", 5432)
        backend.databases = {name: RESTORE.Endpoint("127.0.0.1", 6543, "fixture", "neutral", name)
                             for name in ("source", "drill")}
        for changed in ["other|172.18.0.2|5432", "drill|172.18.0.3|5432", "drill|172.18.0.2|5433"]:
            with self.subTest(fingerprint=changed), patch.object(backend, "sql",
                    side_effect=("source|172.18.0.2|5432", changed)):
                with self.assertRaises(RESTORE.AcceptanceError) as error:
                    backend.identities()
                self.assertNotIn(changed, str(error.exception))
                self.assertEqual(backend.server_identity, ("172.18.0.2", 5432))

    def test_later_address_or_port_drift_cannot_rebind_server(self):
        for changed in ["source|172.18.0.3|5432", "source|172.18.0.2|5433"]:
            backend = RESTORE.PostgresBackend(Path.cwd(), {}, None)
            backend.server_identity = ("172.18.0.2", 5432)
            backend.databases = {name: RESTORE.Endpoint("127.0.0.1", 6543, "fixture", "neutral", name)
                                 for name in ("source", "drill")}
            baseline = ("source|172.18.0.2|5432", "drill|172.18.0.2|5432")
            with self.subTest(fingerprint=changed), patch.object(backend, "sql",
                    side_effect=baseline + (changed, baseline[1])):
                self.assertEqual(backend.identities(), baseline)
                with self.assertRaises(RESTORE.AcceptanceError):
                    backend.identities()
            self.assertEqual(backend.server_identity, ("172.18.0.2", 5432))

    def test_malformed_admin_fingerprint_refuses_before_any_database_mutation(self):
        malformed = ["other|172.18.0.2|5432", "postgres|172.18.0.2/32|5432",
            "postgres|::1/128|5432", "postgres|local|5432", "postgres||5432",
            "postgres|null|5432", "postgres|fe80::1%eth0|5432", "postgres|[::1]|5432",
            "postgres|garbage|5432", "postgres|172.018.0.2|5432",
            "postgres|172.18.0.2|0", "postgres|172.18.0.2|65536",
            "postgres|172.18.0.2|05432", "postgres|172.18.0.2|+5432",
            "postgres|172.18.0.2|null", "postgres|172.18.0.2|5432|extra"]
        admin = RESTORE.parse_admin_url("postgresql://fixture:neutral@127.0.0.1:6543/postgres?sslmode=disable")
        for fingerprint in malformed:
            backend = RESTORE.PostgresBackend(Path.cwd(), {}, admin)
            with self.subTest(fingerprint=fingerprint), tempfile.TemporaryDirectory() as temporary, \
                    patch.object(RESTORE, "private_run_directory", return_value=Path(temporary)), \
                    patch.object(RESTORE, "private_temp_directory", side_effect=reserve_fixture_tmp), \
                    patch.object(RESTORE, "private_json") as private, \
                    patch.object(backend, "sql", return_value=fingerprint) as sql, \
                    patch.object(backend, "invoke") as invoke:
                with self.assertRaises(RESTORE.AcceptanceError) as error:
                    backend.prepare()
                self.assertEqual(sql.call_count, 1)
                self.assertEqual(sql.call_args.args, (admin, RESTORE.IDENTITY_SQL))
                self.assertNotIn(fingerprint, str(error.exception))
                self.assertIsNone(backend.server_identity)
                private.assert_not_called()
                invoke.assert_not_called()

    def test_prepare_cannot_replace_an_existing_server_binding(self):
        backend = RESTORE.PostgresBackend(Path.cwd(), {}, None)
        backend.server_identity = ("172.18.0.2", 5432)
        with patch.object(RESTORE, "private_run_directory") as directory, patch.object(backend, "sql") as sql:
            with self.assertRaises(RESTORE.AcceptanceError):
                backend.prepare()
        directory.assert_not_called()
        sql.assert_not_called()

    def test_windows_fails_closed_before_artifact_or_process_creation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with patch.object(RESTORE.os, "name", "nt"):
                with self.assertRaises(RESTORE.AcceptanceError):
                    RESTORE.private_run_directory(root)
            self.assertEqual(list(root.iterdir()), [])

    @unittest.skipIf(os.name == "nt", "Unix owner-only mode checks")
    def test_private_artifacts_are_exclusive_and_owner_only(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run = RESTORE.private_run_directory(root)
            self.assertEqual(run.stat().st_mode & 0o777, 0o700)
            artifact = run / "credentials.json"
            RESTORE.private_json(artifact, {"token": "neutral-private-fixture"})
            self.assertEqual(artifact.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(RESTORE.AcceptanceError):
                RESTORE.private_json(artifact, {"token": "replacement"})
            self.assertEqual(json.loads(artifact.read_text())["token"], "neutral-private-fixture")

    @unittest.skipIf(os.name == "nt", "Unix symlink test")
    def test_redirected_target_rejected_before_private_write(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "checkout"
            root.mkdir()
            outside = Path(temporary) / "outside"
            outside.mkdir()
            (root / "target").symlink_to(outside, target_is_directory=True)
            with self.assertRaises(RESTORE.AcceptanceError):
                RESTORE.private_run_directory(root)
            self.assertEqual(list(outside.iterdir()), [])

    def test_subprocess_failures_never_expose_arguments_or_captured_secrets(self):
        failure = subprocess.CalledProcessError(1, ["tool", "neutral-password"],
            output="PRIVATE-STDOUT", stderr="PRIVATE-STDERR")
        with patch.object(RESTORE.subprocess, "run", side_effect=failure):
            with self.assertRaises(RESTORE.AcceptanceError) as error:
                RESTORE.checked(["tool", "neutral-password"], env={}, cwd=Path.cwd())
        for value in ["neutral-password", "PRIVATE-STDOUT", "PRIVATE-STDERR"]:
            self.assertNotIn(value, str(error.exception))

    def test_unprepared_subprocess_refuses_before_runner(self):
        calls = []
        backend = RESTORE.PostgresBackend(Path.cwd(), {}, None,
            runner=lambda *args, **kwargs: calls.append((args, kwargs)))
        with self.assertRaises(RESTORE.AcceptanceError):
            backend.invoke(["neutral-tool"])
        self.assertEqual(calls, [])

    @unittest.skipUnless(os.name == "posix", "Unix owner-only temporary ancestry")
    def test_owned_temp_overrides_ambient_and_caller_redirect_in_actual_child(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            owned = root / "tmp"
            owned.mkdir(mode=0o700)
            outside = root / "ambient"
            outside.mkdir(mode=0o700)
            backend = RESTORE.PostgresBackend(Path.cwd(), {}, None)
            backend.run_directory = root
            backend.temp_directory = owned
            script = ("import json,os,tempfile; from pathlib import Path; "
                "fd,path=tempfile.mkstemp(); os.close(fd); "
                "print(json.dumps({'parent':str(Path(path).parent),"
                "'variables':{key:os.environ.get(key) for key in ['TMPDIR','TMP','TEMP']}}))")
            redirected = {key: str(outside) for key in ("TMPDIR", "TMP", "TEMP")}
            with patch.dict(os.environ, redirected):
                result = json.loads(backend.invoke([sys.executable, "-I", "-c", script], redirected))
            self.assertEqual(result["parent"], str(owned))
            self.assertEqual(result["variables"], {key: str(owned) for key in redirected})
            self.assertEqual(list(outside.iterdir()), [])

    @unittest.skipUnless(os.name == "posix", "Unix owner-only temporary ancestry")
    def test_unsafe_temporary_ancestry_refuses_before_runner(self):
        for condition in ("missing", "public-parent", "public-child", "linked-child", "outside-child"):
            with self.subTest(condition=condition), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                child = root / "tmp"
                outside = root / "outside"
                outside.mkdir(mode=0o700)
                if condition == "linked-child":
                    child.symlink_to(outside, target_is_directory=True)
                elif condition != "missing":
                    child.mkdir(mode=0o755 if condition == "public-child" else 0o700)
                if condition == "public-parent":
                    root.chmod(0o755)
                calls = []
                backend = RESTORE.PostgresBackend(Path.cwd(), {}, None,
                    runner=lambda *args, **kwargs: calls.append((args, kwargs)))
                backend.run_directory = root
                backend.temp_directory = outside if condition == "outside-child" else child
                with self.assertRaises(RESTORE.AcceptanceError):
                    backend.invoke(["neutral-tool"])
                self.assertEqual(calls, [])

    @unittest.skipUnless(os.name == "posix", "Unix owner-only temporary ancestry")
    def test_fresh_owned_tmp_precedes_first_admin_probe(self):
        admin = RESTORE.parse_admin_url("postgresql://fixture:neutral@127.0.0.1:5432/postgres?sslmode=disable")
        backend = RESTORE.PostgresBackend(Path.cwd(), {}, admin)
        with tempfile.TemporaryDirectory() as temporary, \
                patch.object(RESTORE, "private_run_directory", return_value=Path(temporary)), \
                patch.object(backend, "sql", return_value="invalid") as sql:
            with self.assertRaises(RESTORE.AcceptanceError):
                backend.prepare()
            owned = Path(temporary) / "tmp"
            self.assertTrue(owned.is_dir())
            self.assertEqual(owned.stat().st_mode & 0o777, 0o700)
            self.assertEqual(backend.temp_directory, owned)
            self.assertEqual(sql.call_args.args, (admin, RESTORE.IDENTITY_SQL))
            with self.assertRaises(RESTORE.AcceptanceError):
                RESTORE.private_temp_directory(Path(temporary))

    @unittest.skipUnless(os.name == "posix", "Unix executable alias dispatch")
    def test_selected_executable_alias_keeps_wrapper_invocation_name(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            wrapper = root / "pg_wrapper"
            wrapper.write_text("#!/bin/sh\ncase \"${0##*/}\" in\n"
                "  psql) printf 'fixture-alias-ok\\n' ;;\n"
                "  *) printf 'wrong-invocation-name\\n' >&2; exit 17 ;;\nesac\n",
                encoding="utf-8")
            wrapper.chmod(0o700)
            alias = root / "psql"
            alias.symlink_to(wrapper)
            chosen = RESTORE.tool_path(str(alias))
            result = subprocess.run([chosen], env={}, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, "fixture-alias-ok\n")
            self.assertEqual(Path(chosen), alias.absolute())

    def test_child_env_removes_provider_redis_pgoptions_and_dotenv_authority(self):
        with patch.dict(os.environ, {"OPENAI_API_KEY": "private-provider", "LLM_FW_WEBHOOK_SIGNING_KEY":
                "private-key", "LLM_FW_REDIS_URL": "private-redis", "PGOPTIONS": "private-options",
                "PGHOSTADDR": "203.0.113.1", "RUST_LOG": "trace"}, clear=True):
            env = RESTORE.child_environment({"LLM_FW_RESTORE_FIXTURE_DATABASE_URL": "neutral-local"})
        for name in ["OPENAI_API_KEY", "LLM_FW_WEBHOOK_SIGNING_KEY", "LLM_FW_REDIS_URL",
                     "PGOPTIONS", "PGHOSTADDR", "RUST_LOG"]:
            self.assertNotIn(name, env)
        self.assertEqual(env["LLM_FW_RESTORE_FIXTURE_DATABASE_URL"], "neutral-local")

    def test_default_cli_does_not_launch_acceptance_tools(self):
        with patch.object(RESTORE, "execute") as run, redirect_stdout(io.StringIO()):
            self.assertEqual(RESTORE.main([]), 0)
        run.assert_not_called()

    def test_helper_output_is_exact_typed_aggregate_contract(self):
        expected = dict(RESTORE.COMMON_RESULT, mode="probe")
        self.assertEqual(RESTORE.helper_result(json.dumps(expected), "probe"), expected)
        for bad in [dict(expected, raw_token="must-not-publish"),
                    dict(expected, retained_token_authenticated=1),
                    dict(expected, pending_deliveries=0), {"error": "must-not-publish"}]:
            with self.assertRaises(RESTORE.AcceptanceError) as error:
                RESTORE.helper_result(json.dumps(bad), "probe")
            self.assertNotIn("must-not-publish", str(error.exception))
        with self.assertRaises(RESTORE.AcceptanceError):
            RESTORE.helper_result('{"mode":"probe","mode":"seed"}', "probe")

    def test_fresh_name_collision_refuses_before_ddl_or_tool_invocation(self):
        backend = RESTORE.PostgresBackend(Path.cwd(), {},
            RESTORE.parse_admin_url("postgresql://fixture:neutral@127.0.0.1:5432/postgres?sslmode=disable"))
        with tempfile.TemporaryDirectory() as temporary, \
                patch.object(RESTORE, "private_run_directory", return_value=Path(temporary)), \
                patch.object(RESTORE, "private_temp_directory", side_effect=reserve_fixture_tmp), \
                patch.object(RESTORE, "private_json"), patch.object(backend, "sql", \
                    side_effect=("postgres|172.18.0.2|5432", "t")) as sql, \
                patch.object(backend, "invoke") as invoke:
            with self.assertRaises(RESTORE.AcceptanceError):
                backend.prepare()
        self.assertEqual(sql.call_count, 2)
        self.assertEqual(sql.call_args_list[0].args, (backend.admin, RESTORE.IDENTITY_SQL))
        self.assertEqual(backend.server_identity, ("172.18.0.2", 5432))
        self.assertTrue(all("CREATE" not in call.args[1] for call in sql.call_args_list))
        invoke.assert_not_called()

    def test_mutation_cannot_use_source_database_or_unbound_target(self):
        backend = RESTORE.PostgresBackend(Path.cwd(), {}, None)
        with patch.object(backend, "invoke") as invoke:
            with self.assertRaises(RESTORE.AcceptanceError):
                backend.helper("exercise-restored", "source", "neutral-target")
            with self.assertRaises(RESTORE.AcceptanceError):
                backend.helper("exercise-restored", "drill")
            with self.assertRaises(RESTORE.AcceptanceError):
                backend.helper("seed", "drill")
        invoke.assert_not_called()

    def test_snapshot_selects_complete_rows_and_keeps_result_private(self):
        endpoint = RESTORE.parse_admin_url("postgresql://fixture:neutral@127.0.0.1:5432/postgres?sslmode=disable")
        backend = RESTORE.PostgresBackend(Path.cwd(), {}, endpoint)
        backend.databases = {"source": endpoint}
        backend.run_directory = Path.cwd()
        catalog = {"tables": ["workspace_service_accounts"], "sequences": []}
        snapshot = {"tables": {"workspace_service_accounts": [
            {"token_hash": "must-stay-private", "active": True, "expires_at_unix": 123}]}, "sequences": {}}
        with patch.object(backend, "sql", side_effect=[json.dumps(catalog), json.dumps(snapshot)]) as sql, \
                patch.object(RESTORE, "private_json") as private:
            self.assertEqual(backend.snapshot("source", "source-before"), snapshot)
        query = sql.call_args_list[1].args[1]
        self.assertIn("to_jsonb(t)", query)
        self.assertIn("REPEATABLE READ READ ONLY", query)
        self.assertEqual(private.call_args.args[1], snapshot)

    def test_main_failure_does_not_copy_tool_transcript_to_evidence(self):
        output = io.StringIO()
        with patch.object(RESTORE, "execute", side_effect=RESTORE.AcceptanceError(
                "An acceptance tool failed; private output was withheld.")), redirect_stdout(output):
            self.assertEqual(RESTORE.main(["--run"]), 1)
        report = json.loads(output.getvalue())
        self.assertEqual(set(report), {"schema_version", "status", "reason"})
        self.assertEqual(report["status"], "failed")


if __name__ == "__main__":
    unittest.main()
