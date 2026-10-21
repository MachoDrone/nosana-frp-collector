#!/usr/bin/env python3
"""Read-only Nosana Docker -> Podman support collector (Python 3 stdlib)."""
import argparse
import collections
import datetime as dt
import json
import os
import re
import subprocess
import sys
import tarfile
import tempfile
import threading
from pathlib import Path

VERSION = '0.1.1'
ROOT = '/var/lib/containers/storage/overlay-containers'
DEFAULT_OUTER = 'podman'
OUTER = DEFAULT_OUTER
MAX_LOG = 16 * 1024 * 1024
MAX_SCAN = 256 * 1024 * 1024
BASE58 = r'[1-9A-HJ-NP-Za-km-z]{32,44}'
FRP_NAME = re.compile(r'^frpc-api-(' + BASE58 + r')$')
SAFE_NAME = re.compile(r'^nosana-node(?:-[A-Za-z0-9_-]+)?$')
ANSI = re.compile(r'\x1b\[[0-?]*[ -/]*[@-~]')
SENSITIVE = re.compile(r'''(?ix)(?:authorization|cookies?|credentials?|signature|private[_ -]?key|secret|mnemonic|password|passwd|seed|token|api[_-]?key|auth\.[\w.]+)["']?\s*[:=]|\bbearer\s+\S+|-----BEGIN .*PRIVATE KEY-----''')
EVENTS = re.compile(r'(?i)node api|api.*(?:offline|online|unreachable)|frpc|router config conflict|proxy.*(?:error|fail|start|rebuild|connect)|(?:dns|name resolution|ENOTFOUND|EAI_AGAIN)|(?:node/info|node\.k8s|host-manager).*?(?:error|fail|timeout|unreachable)')


def clean(text):
    lines, pem = [], False
    for line in ANSI.sub('', text).splitlines():
        line = re.sub(r'^([^ ]+) (?:stdout|stderr) [FP] ', r'\1 ', line)
        if re.fullmatch(r'\d{4}-\d{2}-\d{2}T\S+\s*', line):
            continue
        if '-----BEGIN ' in line and 'PRIVATE KEY-----' in line:
            pem = True
        if pem or SENSITIVE.search(line):
            if not lines or lines[-1] != '[redacted sensitive log line]':
                lines.append('[redacted sensitive log line]')
        else:
            lines.append(''.join(c for c in line if c == '\t' or c.isprintable()))
        if '-----END ' in line and 'PRIVATE KEY-----' in line:
            pem = False
    return '\n'.join(lines)


def command(args, timeout=30, cap=2 * 1024 * 1024):
    """Bound wall time and retained stdout/stderr; never invoke a shell."""
    p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    results = {}
    def drain(stream, key):
        chunks, size, total = collections.deque(), 0, 0
        try:
            while True:
                chunk = stream.read(65536)
                if not chunk:
                    break
                chunks.append(chunk)
                size += len(chunk)
                total += len(chunk)
                while size > cap:
                    excess = size - cap
                    first = chunks.popleft()
                    if len(first) > excess:
                        chunks.appendleft(first[excess:])
                        size -= excess
                    else:
                        size -= len(first)
        finally:
            stream.close()
        results[key] = (b''.join(chunks).decode('utf-8', 'replace'), total > cap)
    threads = [threading.Thread(target=drain, args=(p.stdout, 'out'), daemon=True),
               threading.Thread(target=drain, args=(p.stderr, 'err'), daemon=True)]
    for thread in threads:
        thread.start()
    timed_out = False
    try:
        p.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        p.kill()
        p.wait()
    for thread in threads:
        thread.join(timeout=3)
    if any(thread.is_alive() for thread in threads):
        raise RuntimeError('command output did not close within the collection limit')
    out, cut = results['out']
    err, _ = results['err']
    if timed_out:
        raise RuntimeError('command exceeded %ss' % timeout)
    if p.returncode:
        raise RuntimeError(clean(err[-1500:]) or 'command failed (%s)' % p.returncode)
    return out, cut


def copied_file(path, limit, tail=False):
    """Read one exact file via docker cp's tar stream without extracting it."""
    with tempfile.TemporaryFile() as err:
        p = subprocess.Popen(['docker', 'cp', OUTER + ':' + path, '-'],
                             stdout=subprocess.PIPE, stderr=err)
        expired = threading.Event()
        def stop():
            expired.set()
            p.kill()
        timer = threading.Timer(30, stop)
        timer.start()
        try:
            with tarfile.open(fileobj=p.stdout, mode='r|*') as archive:
                member = next((m for m in archive if m.isfile()), None)
                if member is None:
                    raise RuntimeError('requested file was not present in copy stream')
                if not tail and member.size > limit:
                    raise RuntimeError('metadata exceeds safety size limit')
                stream = archive.extractfile(member)
                chunks, size, scanned = collections.deque(), 0, 0
                while scanned < MAX_SCAN:
                    chunk = stream.read(min(65536, MAX_SCAN - scanned))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    size += len(chunk)
                    scanned += len(chunk)
                    while size > limit:
                        first = chunks.popleft()
                        excess = size - limit
                        if len(first) > excess:
                            chunks.appendleft(first[excess:])
                            size -= excess
                        else:
                            size -= len(first)
                if scanned < member.size:
                    p.kill()
                    raise RuntimeError('log exceeds 256 MiB scan limit; omitted')
                data = b''.join(chunks)
                truncated = member.size > limit
                if truncated:
                    data = data.partition(b'\n')[2]
            # Drain tar padding before closing the pipe so Docker can exit cleanly.
            remaining = 0
            while True:
                padding = p.stdout.read(65536)
                if not padding:
                    break
                remaining += len(padding)
                if remaining > 1024 * 1024:
                    raise RuntimeError('unexpected extra data in copy stream')
            p.stdout.close()
            p.wait(timeout=3)
            if expired.is_set():
                raise RuntimeError('file copy exceeded 30s')
            if p.returncode:
                err.seek(0)
                raise RuntimeError(clean(err.read(1500).decode('utf-8', 'replace')))
            return data.decode('utf-8', 'replace'), truncated
        finally:
            timer.cancel()
            if p.poll() is None:
                p.kill()
            p.wait()
            p.stdout.close()


def outer_state():
    template = '{{json .State.Status}}|{{json .State.StartedAt}}|{{json .State.FinishedAt}}|{{json .State.ExitCode}}|{{json .State.OOMKilled}}|{{json .RestartCount}}'
    raw, _ = command(['docker', 'inspect', '--format', template, OUTER])
    return dict(zip(('status', 'started', 'finished', 'exitCode', 'oomKilled', 'restartCount'),
                    (json.loads(v) for v in raw.strip().split('|'))))


def inner_state(cid):
    template = '{{json .State.Status}}|{{json .State.StartedAt}}|{{json .State.FinishedAt}}|{{json .State.ExitCode}}|{{json .State.OOMKilled}}|{{json .ImageName}}'
    raw, _ = command(['docker', 'exec', OUTER, 'timeout', '-k', '2s', '10s', 'podman', 'inspect', '--format', template, cid])
    return dict(zip(('status', 'started', 'finished', 'exitCode', 'oomKilled', 'image'),
                    (json.loads(v) for v in raw.strip().split('|'))))


def configuration(log, address):
    cfg = {}
    for field in ('serverAddr', 'serverPort', 'localIp', 'localPort'):
        matches = re.findall(r'\b' + field + r'\s*=\s*(?:"([^"\n]+)"|(\d+))', log)
        if matches:
            cfg[field] = next(v for v in matches[-1] if v)
    server = cfg.get('serverAddr', '')
    if not re.fullmatch(r'[A-Za-z0-9.-]+\.(?:nos\.ci|nosana\.io)', server) or '..' in server:
        cfg.pop('serverAddr', None)
    if not SAFE_NAME.fullmatch(cfg.get('localIp', '')):
        cfg.pop('localIp', None)
    port = cfg.get('localPort', '')
    if not port.isdigit() or not 1 <= int(port) <= 65535:
        cfg.pop('localPort', None)
    expected = address + '.' + server
    domains = re.findall(r'\bcustomDomains\s*=\s*\[([^\n]*)\]', log)
    cfg['domainVerifiedInLog'] = bool(domains and ('"' + expected + '"') in domains[-1])
    return cfg


CHECK_JS = r'''
const dns = require('dns').promises;
const http = require('http'), https = require('https');
const c = JSON.parse(process.argv[1]);
const checkedAt = Date.now();
const lookup = async h => {
 let timer;
 try { return {host:h, addresses: await Promise.race([
   dns.lookup(h,{all:true}).then(a=>a.map(x=>x.address)),
   new Promise((_,r)=>{timer=setTimeout(()=>r(new Error('DNS timeout')),3000)})])}; }
 catch(e){return {host:h,error:e.code||e.message};} finally{clearTimeout(timer);}
};
const get = (url, info=false) => new Promise(resolve=>{
 let done=false, size=0, body='', timer;
 const finish=x=>{if(!done){done=true;clearTimeout(timer);resolve({url,...x});}};
 const req=(url.startsWith('https:')?https:http).get(url,res=>{
  res.on('data',b=>{size+=b.length;if(size<=(info?65536:2048))body+=b.toString();else{finish({status:res.statusCode,error:'response exceeded collection limit'});req.destroy();}});
  res.on('end',()=>{let parsed;try{parsed=JSON.parse(body)}catch{};
   finish(info?{status:res.statusCode,jsonObject:!!parsed&&typeof parsed==='object'&&!Array.isArray(parsed),packageVersion:typeof parsed?.info?.version==='string'&&/^[0-9A-Za-z.+-]{1,60}$/.test(parsed.info.version)?parsed.info.version:undefined}:{status:res.statusCode,identityMatched:parsed===c.address||!!(parsed&&parsed.address===c.address)});});
  res.on('error',e=>finish({error:e.code||e.message}));
 });
 timer=setTimeout(()=>{finish({error:'request timeout after 8s'});req.destroy();},8000);
 req.on('error',e=>finish({error:e.code||e.message}));
});
(async()=>{const r=await Promise.all([
 lookup(c.server),lookup('host-manager.k8s.prd.nos.ci'),
 get('http://127.0.0.1:'+c.port+'/'),get('https://'+c.address+'.'+c.server+'/'),
 get('http://127.0.0.1:'+c.port+'/node/info',true),get('https://'+c.address+'.'+c.server+'/node/info',true)
]);process.stdout.write(JSON.stringify({checkedAtUTC:new Date(checkedAt).toISOString(),elapsedMs:Date.now()-checkedAt,dns:r.slice(0,2),local:r[2],public:r[3],localInfo:r[4],publicInfo:r[5]}),()=>process.exit(0));})().catch(()=>process.exit(1));
'''


def current_checks(node_id, cfg, address):
    data = json.dumps({'server': cfg['serverAddr'], 'port': int(cfg['localPort']), 'address': address})
    raw, _ = command(['docker', 'exec', OUTER, 'timeout', '-k', '2s', '15s', 'podman', 'exec', node_id,
                      'node', '-e', CHECK_JS, data], timeout=20, cap=16384)
    return json.loads(raw)


def event_timestamp(line):
    match = re.search(r'\d{4}-\d{2}-\d{2}T\S+|\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?', line)
    return match.group(0) if match else '[timestamp unavailable]'


def check_description(result):
    if result.get('status') == 200 and result.get('identityMatched'):
        return 'reachable now; HTTP 200 and expected node identity verified'
    if 'error' in result:
        return 'check failed: ' + result['error'] + ('; HTTP ' + str(result['status']) if 'status' in result else '')
    identity = 'verified, but response is not successful' if result.get('identityMatched') else 'NOT verified'
    return 'HTTP %s; expected node identity %s' % (result.get('status', 'unknown'), identity)


def info_description(result):
    if result.get('status') == 200 and result.get('jsonObject'):
        return 'HTTP 200; JSON object received' + ('; package ' + result['packageVersion'] if result.get('packageVersion') else '')
    return 'check failed: ' + result.get('error', 'HTTP %s; expected JSON object not confirmed' % result.get('status', 'unknown'))


def arguments(argv=None):
    parser = argparse.ArgumentParser(
        description='Read-only diagnostics for Nosana hosts using Docker with nested Podman. '
                    'Print a support summary and save a private text report; no reports are uploaded.')
    parser.add_argument('--version', action='version', version='nosana-frp-collector ' + VERSION)
    parser.add_argument('--container', default=DEFAULT_OUTER, metavar='NAME',
                        help='outer Docker container name (default: podman)')
    parser.add_argument('--output-dir', default='.', metavar='PATH',
                        help='existing directory for the report (default: current directory)')
    parser.add_argument('--logs-only', action='store_true',
                        help='collect state and retained logs without DNS or HTTP probes')
    options = parser.parse_args(argv)
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', options.container):
        parser.error('--container must be a valid Docker container name or ID')
    options.output_dir = Path(options.output_dir).expanduser().resolve()
    if not options.output_dir.is_dir():
        parser.error('--output-dir must be an existing directory')
    return options


def main(argv=None):
    global OUTER
    options = arguments(argv)
    OUTER = options.container
    os.umask(0o077)
    collected = dt.datetime.now(dt.timezone.utc)
    stamp = collected.strftime('%Y%m%dT%H%M%S.%fZ')
    hostname = os.uname().nodename
    report = options.output_dir / ('nosana-frp-%s-%s.txt' % (re.sub(r'[^A-Za-z0-9_.-]', '_', hostname), stamp))
    print('Collecting read-only diagnostics from Docker container %s...' % OUTER, flush=True)
    state = outer_state()
    raw, _ = copied_file(ROOT + '/containers.json', 8 * 1024 * 1024)
    index = json.loads(raw)
    if not isinstance(index, list):
        raise RuntimeError('unrecognized Podman container metadata')
    known, frps = {}, []
    for item in index:
        cid = item.get('id', '')
        if not re.fullmatch(r'[0-9a-f]{64}', cid):
            continue
        for name in item.get('names', []):
            if SAFE_NAME.fullmatch(name):
                known[name] = cid
            match = FRP_NAME.fullmatch(name)
            if match:
                frps.append((cid, name, match.group(1)))
    summary = ['NOSANA FRP SUMMARY', 'Collector version: ' + VERSION,
               'PC: ' + hostname, 'Collected UTC: ' + collected.isoformat(),
               'Outer Docker container %s: %s' % (OUTER, state['status']),
               'Retained FRP API containers: ' + str(len(frps))]
    details = ['SELECTED OUTER CONTAINER STATE', json.dumps(state, indent=2)]
    screen = []
    if not frps:
        summary.append('No retained FRP API container records found; deleted containers may have lost their logs.')
    for cid, name, address in frps:
        print('Reading retained logs for %s...' % name, flush=True)
        summary.extend(['', 'Node: ' + address])
        details.extend(['', 'FRP CONTAINER: ' + name, 'ID: ' + cid])
        try:
            log, truncated = copied_file(ROOT + '/' + cid + '/userdata/ctr.log', MAX_LOG, tail=True)
            log = clean(log)
            label = 'Historical FRP log' + (' (last 16 MiB only; truncated)' if truncated else ' (retained file)')
            details.extend([label, log or '[empty]'])
            screen.extend(['', name + ': last 60 retained log lines', '\n'.join(log.splitlines()[-60:]) or '[empty]'])
            successes = [line for line in log.splitlines() if 'start proxy success' in line]
            conflicts = [line for line in log.splitlines() if 'router config conflict' in line]
            summary.append('Historical registration successes: %d; route conflicts: %d (retained log only)' % (len(successes), len(conflicts)))
            if successes:
                summary.append('Latest retained registration success: ' + event_timestamp(successes[-1]))
            if conflicts:
                summary.append('Latest retained conflict: ' + event_timestamp(conflicts[-1]))
            cfg = configuration(log, address)
            details.extend(['Validated routing fields from historical log', json.dumps(cfg, indent=2)])
        except Exception as error:
            summary.append('FRP log unavailable: ' + clean(str(error)))
            cfg = {}
        if state['status'] == 'running':
            try:
                frp_state = inner_state(cid)
                summary.append('FRP container now: ' + frp_state['status'])
                details.extend(['Current FRP state', json.dumps(frp_state, indent=2)])
            except Exception as error:
                summary.append('Current FRP state unavailable: ' + clean(str(error)))
        else:
            summary.append('Current inner state/DNS/HTTP checks unavailable: outer container is not running.')
        node_name = cfg.get('localIp')
        node_id = known.get(node_name)
        if not node_id:
            summary.append('Matching node container not verified from retained routing config; node-specific checks skipped.')
            continue
        try:
            node_state = {'status': 'unavailable'}
            if state['status'] == 'running':
                node_state = inner_state(node_id)
                summary.append('Matching node container %s now: %s' % (node_name, node_state['status']))
                details.extend(['Current matching node state', json.dumps(node_state, indent=2)])
            try:
                if state['status'] == 'running':
                    events, cut = command(['docker', 'exec', OUTER, 'timeout', '-k', '2s', '10s',
                                           'tail', '-c', '2097152', ROOT + '/' + node_id + '/userdata/ctr.log'], timeout=15)
                else:
                    events, cut = copied_file(ROOT + '/' + node_id + '/userdata/ctr.log', 2097152, tail=True)
                selected = [line for line in clean(events).splitlines() if EVENTS.search(line)]
                event_label = 'Matching node API/DNS events (filtered from last 2 MiB of retained log; dates shown%s)' % (', capture truncated' if cut else '')
                details.extend([event_label, '\n'.join(selected) or '[no matching lines]'])
                screen.extend(['', event_label + ': last 30 matches', '\n'.join(selected[-30:]) or '[no matching lines]'])
            except Exception as error:
                details.append('Matching node log unavailable: ' + clean(str(error)))
                summary.append('Matching node API/DNS event log unavailable; current checks continue.')
            if options.logs_only:
                summary.append('Current DNS/HTTP checks skipped: --logs-only selected.')
            elif state['status'] != 'running':
                summary.append('Current DNS/HTTP checks skipped; retained node events above are historical only.')
            elif node_state['status'] != 'running':
                summary.append('Current DNS/HTTP checks skipped: matching node container is stopped.')
            elif all(cfg.get(k) for k in ('serverAddr', 'localPort', 'domainVerifiedInLog')):
                checks = current_checks(node_id, cfg, address)
                summary.append('Current checks UTC: %s (%s ms)' % (checks.get('checkedAtUTC', 'unknown'), checks.get('elapsedMs', 'unknown')))
                summary.append('Local API root identity: ' + check_description(checks['local']))
                summary.append('Public API root identity: ' + check_description(checks['public']))
                summary.append('Local /node/info: ' + info_description(checks['localInfo']))
                summary.append('Public /node/info: ' + info_description(checks['publicInfo']))
                for item in checks['dns']:
                    summary.append('DNS from node container for %s: %s' % (item['host'], item.get('error') or ', '.join(item.get('addresses', []))))
                details.extend(['Current checks from matching node container', json.dumps(checks, indent=2)])
            else:
                summary.append('Current DNS/HTTP checks skipped: complete approved routing fields not verified in retained log.')
        except Exception as error:
            summary.append('Matching node collection/check unavailable: ' + clean(str(error)))
    limits = ('Read-only collection; no containers started/restarted and no settings changed. '\
              'HTTP checks are unauthenticated GETs of / and /node/info from the matching node container; job routes are not tested. '\
              'No keys, signatures or benchmark jobs used. '\
              'Historical log success does not establish current reachability. Current DNS checks do not prove past DNS health. '\
              'FRP server route ownership cannot be determined from these client logs. '\
              'Logs may rotate/change during collection; deleted records and alternative storage layouts may be unavailable. '\
              'Sensitive assignment lines are redacted; review the report before sharing.')
    text = '\n'.join(summary + ['', limits, ''] + details) + '\n'
    with report.open('x', encoding='utf-8') as output:
        output.write(text)
    print('\n'.join(screen + ['', limits, ''] + summary))
    print('\nSend this file: ' + str(report.resolve()))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print('Collection stopped: ' + clean(str(error)), file=sys.stderr)
        sys.exit(1)
