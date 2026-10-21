"""Offline contract tests: synthetic logs, no Docker daemon or network required."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


PROJECT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('nosana_collector_under_test', PROJECT / 'collector.py')
collector = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(collector)
ADDRESS_A = 'A' * 44
ADDRESS_B = 'B' * 44
FRP_A = 'a' * 64
FRP_B = 'b' * 64
NODE_A = 'c' * 64
NODE_B = 'd' * 64
SERVER = 'node.k8s.prd.nos.ci'
STAMP = '2026-01-02T03:04:05Z'


def route_log(address=ADDRESS_A, node='nosana-node-a'):
    return '\n'.join([
        f'{STAMP} stdout F serverAddr = "{SERVER}"',
        f'{STAMP} stdout F serverPort = 7000',
        f'{STAMP} stdout F localIp = "{node}"',
        f'{STAMP} stdout F localPort = 5001',
        f'{STAMP} stdout F customDomains = ["{address}.{SERVER}"]',
        f'{STAMP} stdout F start proxy success',
    ])


def checked_results():
    return {
        'checkedAtUTC': STAMP,
        'elapsedMs': 100,
        'local': {'status': 200, 'identityMatched': True},
        'public': {'status': 200, 'identityMatched': False},
        'localInfo': {'status': 200, 'jsonObject': True, 'packageVersion': '1.2.3'},
        'publicInfo': {'status': 503, 'jsonObject': False},
        'dns': [{'host': SERVER, 'addresses': ['192.0.2.10']}],
    }


class RedactionTests(unittest.TestCase):
    def test_credentials_and_entire_private_key_block_are_removed(self):
        original = '\n'.join([
            'normal startup',
            'Authorization: Bearer fixture-bearer',
            'auth.token = "fixture-frp-token"',
            '{"privateKey": "fixture-private-key"}',
            'Cookie: session=fixture-session',
            'password=fixture-password',
            'mnemonic: fixture-mnemonic',
            '-----BEGIN OPENSSH PRIVATE KEY-----',
            'fixture-key-body-one',
            'fixture-key-body-two',
            '-----END OPENSSH PRIVATE KEY-----',
            'start proxy success',
        ])
        rendered = collector.clean(original)
        self.assertIn('normal startup', rendered)
        self.assertIn('start proxy success', rendered)
        self.assertIn('redacted', rendered)
        for secret in ('fixture-bearer', 'fixture-frp-token', 'fixture-private-key',
                       'fixture-session', 'fixture-password', 'fixture-mnemonic',
                       'fixture-key-body-one', 'fixture-key-body-two'):
            with self.subTest(secret=secret):
                self.assertNotIn(secret, rendered)

    def test_terminal_controls_removed_without_losing_timestamp_or_event(self):
        original = f'{STAMP} stdout F \x1b[31mrouter config conflict\x1b[0m\x00\x07\n{STAMP} stderr F \n'
        rendered = collector.clean(original)
        self.assertEqual(rendered, f'{STAMP} router config conflict')
        self.assertNotIn('\x1b', rendered)
        self.assertNotIn('\x00', rendered)
        self.assertNotIn('\x07', rendered)

    def test_unterminated_private_key_block_stays_redacted_to_end(self):
        rendered = collector.clean('before\n-----BEGIN PRIVATE KEY-----\nfixture-secret-body\nmore-key-data')
        self.assertIn('before', rendered)
        self.assertNotIn('fixture-secret-body', rendered)
        self.assertNotIn('more-key-data', rendered)


class RoutingAndStatusTests(unittest.TestCase):
    def test_expected_routing_tuple_is_verified(self):
        cfg = collector.configuration(route_log(), ADDRESS_A)
        self.assertEqual(cfg['serverAddr'], SERVER)
        self.assertEqual(cfg['localIp'], 'nosana-node-a')
        self.assertEqual(cfg['localPort'], '5001')
        self.assertTrue(cfg['domainVerifiedInLog'])

    def test_arbitrary_hosts_paths_and_ports_cannot_be_used_for_live_checks(self):
        for value in ('example.invalid', 'node.nos.ci.evil.invalid', '127.0.0.1',
                      'node..nos.ci', 'https://node.nos.ci', 'node.nos.ci/path',
                      'user@node.nos.ci'):
            with self.subTest(server=value):
                log = route_log().replace(SERVER, value)
                self.assertNotIn('serverAddr', collector.configuration(log, ADDRESS_A))
        for value in ('../../private', '/etc/shadow', 'other-container',
                      'nosana-node;id', 'nosana-node/../other'):
            with self.subTest(node=value):
                log = route_log().replace('nosana-node-a', value)
                self.assertNotIn('localIp', collector.configuration(log, ADDRESS_A))
        for value in ('0', '65536', '-1', '5001/path'):
            with self.subTest(port=value):
                log = route_log().replace('localPort = 5001', 'localPort = "' + value + '"')
                self.assertNotIn('localPort', collector.configuration(log, ADDRESS_A))

    def test_subdomain_must_match_this_node_and_latest_config(self):
        log = route_log().replace(f'customDomains = ["{ADDRESS_A}.', f'customDomains = ["{ADDRESS_B}.')
        self.assertFalse(collector.configuration(log, ADDRESS_A)['domainVerifiedInLog'])
        log = route_log() + '\ncustomDomains = ["unrelated.example.invalid"]'
        self.assertFalse(collector.configuration(log, ADDRESS_A)['domainVerifiedInLog'])

    def test_node_container_names_exclude_arbitrary_paths_and_non_base58_addresses(self):
        self.assertTrue(collector.FRP_NAME.fullmatch('frpc-api-' + ADDRESS_A))
        for name in ('frpc-api-' + '0' * 44, 'frpc-api-' + ADDRESS_A + '/etc/shadow',
                     'frpc-api-' + ADDRESS_A + ';id', 'frpc-api-short'):
            with self.subTest(name=name):
                self.assertIsNone(collector.FRP_NAME.fullmatch(name))

    def test_http_200_requires_the_expected_identity(self):
        good = collector.check_description({'status': 200, 'identityMatched': True})
        wrong = collector.check_description({'status': 200, 'identityMatched': False})
        failed = collector.check_description({'status': 503, 'identityMatched': True})
        timeout = collector.check_description({'error': 'request timeout'})
        self.assertIn('reachable now', good)
        self.assertIn('NOT verified', wrong)
        self.assertNotIn('reachable now', wrong)
        self.assertNotIn('reachable now', failed)
        self.assertIn('not successful', failed)
        self.assertIn('request timeout', timeout)

    def test_node_info_needs_successful_status_and_a_json_object(self):
        self.assertIn('package 1.2.3', collector.info_description(
            {'status': 200, 'jsonObject': True, 'packageVersion': '1.2.3'}))
        for result in ({'status': 200, 'jsonObject': False},
                       {'status': 503, 'jsonObject': True}, {'error': 'ECONNREFUSED'}):
            with self.subTest(result=result):
                self.assertIn('check failed', collector.info_description(result))


class MainCollectionTests(unittest.TestCase):
    def collect(self, status='exited', missing=(), extra_args=()):
        """All Docker and live-check entry points are replaced by bounded fixtures."""
        records = [
            {'id': FRP_A, 'names': ['frpc-api-' + ADDRESS_A]},
            {'id': NODE_A, 'names': ['nosana-node-a']},
            {'id': FRP_B, 'names': ['frpc-api-' + ADDRESS_B]},
            {'id': NODE_B, 'names': ['nosana-node-b']},
            {'id': '../../outside', 'names': ['frpc-api-' + ADDRESS_A]},
            {'id': 'e' * 64, 'names': ['unrelated-container']},
        ]
        fixture_files = {
            collector.ROOT + '/containers.json': json.dumps(records),
            collector.ROOT + '/' + FRP_A + '/userdata/ctr.log': route_log(),
            collector.ROOT + '/' + FRP_B + '/userdata/ctr.log': route_log(ADDRESS_B, 'nosana-node-b'),
            collector.ROOT + '/' + NODE_A + '/userdata/ctr.log': f'{STAMP} stderr F Node API is detected offline\npassword=fixture-password\n',
            collector.ROOT + '/' + NODE_B + '/userdata/ctr.log': f'{STAMP} stderr F DNS EAI_AGAIN while checking node API\n',
        }
        read_paths, commands = [], []

        def read_fixture(path, limit, tail=False):
            self.assertIn(path, fixture_files, 'collector read an unapproved path')
            read_paths.append(path)
            if any('/' + cid + '/' in path for cid in missing):
                raise RuntimeError('fixture log rotated away')
            return fixture_files[path], False

        def command_fixture(args, **kwargs):
            commands.append(args)
            # Main only needs a file tail when its running node's retained log is read.
            self.assertEqual(args[:8], ['docker', 'exec', collector.OUTER, 'timeout', '-k', '2s', '10s', 'tail'])
            self.assertEqual(args[8:10], ['-c', '2097152'])
            return read_fixture(args[10], 2097152, tail=True)

        with tempfile.TemporaryDirectory() as temporary:
            with contextlib.ExitStack() as stack:
                stack.enter_context(mock.patch.object(collector, 'outer_state', return_value={
                    'status': status, 'started': STAMP, 'finished': STAMP,
                    'exitCode': 0, 'oomKilled': False, 'restartCount': 0}))
                stack.enter_context(mock.patch.object(collector, 'copied_file', side_effect=read_fixture))
                inner = stack.enter_context(mock.patch.object(collector, 'inner_state', return_value={
                    'status': 'running', 'started': STAMP, 'image': 'fixture/image:1'}))
                checks = stack.enter_context(mock.patch.object(collector, 'current_checks', return_value=checked_results()))
                stack.enter_context(mock.patch.object(collector, 'command', side_effect=command_fixture))
                stack.enter_context(mock.patch.object(collector.os, 'uname', return_value=SimpleNamespace(nodename='fixture-host')))
                previous_umask = os.umask(0o077)
                stack.callback(os.umask, previous_umask)
                screen = io.StringIO()
                stack.enter_context(contextlib.redirect_stdout(screen))
                result = collector.main(['--output-dir', temporary, *extra_args])
                reports = list(Path(temporary).glob('nosana-frp-*.txt'))
                self.assertEqual(len(reports), 1)
                report = reports[0].read_text()
                self.assertIn('Send this file: ' + str(reports[0]), screen.getvalue())
                self.assertEqual(reports[0].stat().st_mode & 0o077, 0)
                self.assertNotIn('fixture-password', report)
                self.assertNotIn('fixture-password', screen.getvalue())
                return SimpleNamespace(report=report, screen=screen.getvalue(), read_paths=read_paths,
                                       commands=commands, inner=inner, checks=checks, result=result)

    def test_stopped_outer_collects_both_retained_logs_without_exec_or_network(self):
        run = self.collect(status='exited')
        run.inner.assert_not_called()
        run.checks.assert_not_called()
        self.assertEqual(run.commands, [])
        self.assertIn(collector.ROOT + '/' + NODE_A + '/userdata/ctr.log', run.read_paths)
        self.assertIn(collector.ROOT + '/' + NODE_B + '/userdata/ctr.log', run.read_paths)
        self.assertIn('Node API is detected offline', run.report)
        self.assertIn('DNS EAI_AGAIN', run.report)
        self.assertIn('historical only', run.report)
        self.assertNotIn('reachable now;', run.report)

    def test_running_outer_keeps_checks_read_only_and_reports_identity_mismatch(self):
        run = self.collect(status='running')
        self.assertEqual(run.inner.call_count, 4)
        self.assertEqual(run.checks.call_count, 2)
        self.assertEqual(len(run.commands), 2)
        self.assertIn('Local API root identity: reachable now;', run.report)
        self.assertIn('Public API root identity: HTTP 200; expected node identity NOT verified', run.report)
        self.assertIn('Public /node/info: check failed:', run.report)
        for call in run.checks.call_args_list:
            cid, cfg, address = call.args
            self.assertIn(cid, (NODE_A, NODE_B))
            self.assertIn(address, (ADDRESS_A, ADDRESS_B))
            self.assertEqual(cfg['serverAddr'], SERVER)
            self.assertTrue(cfg['domainVerifiedInLog'])

    def test_logs_only_suppresses_live_dns_and_http_checks(self):
        run = self.collect(status='running', extra_args=('--logs-only',))
        run.checks.assert_not_called()
        self.assertIn('Node API is detected offline', run.report)
        self.assertNotIn('reachable now;', run.report)

    def test_missing_frp_log_does_not_abort_other_nodes(self):
        run = self.collect(status='exited', missing=(FRP_A,))
        self.assertIn('FRP log unavailable:', run.report)
        self.assertIn('fixture log rotated away', run.report)
        self.assertIn('Node: ' + ADDRESS_B, run.report)
        self.assertIn('DNS EAI_AGAIN', run.report)

    def test_missing_node_log_does_not_prevent_current_checks(self):
        run = self.collect(status='running', missing=(NODE_A,))
        self.assertIn('Matching node log unavailable:', run.report)
        self.assertEqual(run.checks.call_count, 2)
        self.assertIn('DNS EAI_AGAIN', run.report)


class SubprocessBoundariesTests(unittest.TestCase):
    def test_command_caps_retained_output_and_drains_both_streams(self):
        code = 'import sys; sys.stdout.write("x" * 131072 + "END"); sys.stderr.write("e" * 131072)'
        output, truncated = collector.command([sys.executable, '-c', code], timeout=5, cap=128)
        self.assertTrue(truncated)
        self.assertEqual(len(output), 128)
        self.assertTrue(output.endswith('END'))

    def test_command_failure_redacts_stderr_credentials(self):
        code = 'import sys; sys.stderr.write("password=fixture-command-secret\\nnormal failure\\n"); sys.exit(2)'
        with self.assertRaises(RuntimeError) as error:
            collector.command([sys.executable, '-c', code], timeout=5)
        self.assertIn('normal failure', str(error.exception))
        self.assertNotIn('fixture-command-secret', str(error.exception))

    def test_current_checks_constructs_only_the_expected_node_exec(self):
        cfg = collector.configuration(route_log(), ADDRESS_A)
        with mock.patch.object(collector, 'command', return_value=(json.dumps(checked_results()), False)) as command:
            collector.current_checks(NODE_A, cfg, ADDRESS_A)
        args = command.call_args.args[0]
        self.assertEqual(args[:10], ['docker', 'exec', collector.OUTER, 'timeout', '-k', '2s', '15s', 'podman', 'exec', NODE_A])
        self.assertEqual(args[10:12], ['node', '-e'])
        self.assertEqual(json.loads(args[-1]), {'server': SERVER, 'port': 5001, 'address': ADDRESS_A})


class CopiedFileTests(unittest.TestCase):
    @contextlib.contextmanager
    def fake_docker(self, content=None, symlink=False):
        """A real subprocess streams a fixture tar; Docker itself is never invoked."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive_path = root / 'fixture.tar'
            with tarfile.open(archive_path, 'w') as archive:
                entry = tarfile.TarInfo('ctr.log')
                if symlink:
                    entry.type = tarfile.SYMTYPE
                    entry.linkname = '/outside-fixture/private-file'
                    archive.addfile(entry)
                else:
                    entry.size = len(content)
                    archive.addfile(entry, io.BytesIO(content))
            executable = root / 'docker'
            executable.write_text(
                '#!' + sys.executable + '\n'
                'import pathlib, sys\n'
                'if sys.argv[1:] != ["cp", "podman:/fixture/ctr.log", "-"]: sys.exit(91)\n'
                'sys.stdout.buffer.write(pathlib.Path(' + repr(str(archive_path)) + ').read_bytes())\n')
            executable.chmod(0o755)
            with mock.patch.dict(os.environ, {'PATH': str(root)}), mock.patch.object(collector, 'OUTER', 'podman'):
                yield root

    def test_tar_stream_is_read_without_extracting_files(self):
        with self.fake_docker(b'first event\nlast event\n') as root:
            text, truncated = collector.copied_file('/fixture/ctr.log', limit=1024)
            self.assertEqual(text, 'first event\nlast event\n')
            self.assertFalse(truncated)
            self.assertFalse((root / 'ctr.log').exists())

    def test_log_tail_is_bounded_and_drops_partial_first_line(self):
        with self.fake_docker(b'older-long-line\nnew event\nlast event\n'):
            text, truncated = collector.copied_file('/fixture/ctr.log', limit=25, tail=True)
            self.assertTrue(truncated)
            self.assertEqual(text, 'new event\nlast event\n')
            self.assertLessEqual(len(text), 25)

    def test_oversized_metadata_is_rejected_instead_of_truncated_json(self):
        with self.fake_docker(b'x' * 100):
            with self.assertRaisesRegex(RuntimeError, 'metadata exceeds'):
                collector.copied_file('/fixture/ctr.log', limit=10)

    def test_scan_limit_does_not_silently_claim_the_prefix_is_a_tail(self):
        with self.fake_docker(b'x' * 2048), mock.patch.object(collector, 'MAX_SCAN', 1024):
            with self.assertRaisesRegex(RuntimeError, 'scan limit'):
                collector.copied_file('/fixture/ctr.log', limit=64, tail=True)

    def test_symlink_is_not_followed_or_extracted(self):
        with self.fake_docker(symlink=True) as root:
            with self.assertRaisesRegex(RuntimeError, 'not present'):
                collector.copied_file('/fixture/ctr.log', limit=1024)
            self.assertFalse((root / 'ctr.log').exists())


if __name__ == '__main__':
    unittest.main()
