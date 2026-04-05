import json
import os
import re
import shutil
import socket
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

SAFE_RESULT_LIMIT = 8000


def truncate_text(value: str, limit: int = SAFE_RESULT_LIMIT) -> str:
    if len(value) <= limit:
        return value
    return value[: limit - 18] + '\n...[truncated]'


def mask_secrets(value: str) -> str:
    masked = re.sub(r'(?i)(password|passwd|token|secret|apikey|api_key)\s*[:=]\s*[^\s,;]+', r'\1=***', value)
    return masked


def format_result(payload: dict) -> str:
    return truncate_text(mask_secrets(json.dumps(payload, ensure_ascii=False)))


def safe_run(args: list[str], timeout: int = 6) -> subprocess.CompletedProcess:
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)


def _read_load() -> dict:
    one, five, fifteen = os.getloadavg()
    return {'1m': round(one, 2), '5m': round(five, 2), '15m': round(fifteen, 2)}


def _per_core_usage() -> list[float]:
    def read_stat() -> list[tuple[int, int]]:
        rows = []
        with open('/proc/stat', 'r', encoding='utf-8') as f:
            for line in f:
                if not line.startswith('cpu') or line.startswith('cpu '):
                    continue
                parts = line.split()
                vals = [int(x) for x in parts[1:]]
                idle = vals[3] + vals[4]
                total = sum(vals)
                rows.append((total, idle))
        return rows

    first = read_stat()
    time.sleep(0.2)
    second = read_stat()
    cores = []
    for (t1, i1), (t2, i2) in zip(first, second):
        total = max(t2 - t1, 1)
        idle = max(i2 - i1, 0)
        cores.append(round((1 - idle / total) * 100, 1))
    return cores


def check_cpu_advanced(params: dict) -> dict:
    cores = _per_core_usage()
    load = _read_load()
    threshold_warn = float(params.get('warn_load_per_cpu', 1.0))
    cpu_count = os.cpu_count() or 1
    load_per_cpu = load['1m'] / cpu_count
    level = 'OK'
    if load_per_cpu >= threshold_warn * 1.5:
        level = 'CRIT'
    elif load_per_cpu >= threshold_warn:
        level = 'WARN'
    return {
        'level': level,
        'summary': f'CPU load 1m={load["1m"]} ({load_per_cpu:.2f}/CPU), cores_busy_max={max(cores) if cores else 0}%',
        'metrics': {'load_avg': load, 'cpu_count': cpu_count, 'per_core_usage_percent': cores},
    }


def _read_meminfo() -> dict[str, int]:
    data: dict[str, int] = {}
    with open('/proc/meminfo', 'r', encoding='utf-8') as f:
        for line in f:
            k, v = line.split(':', 1)
            data[k] = int(v.strip().split()[0])
    return data


def check_memory_advanced(params: dict) -> dict:
    mem = _read_meminfo()
    total = mem.get('MemTotal', 0)
    avail = mem.get('MemAvailable', 0)
    used = max(total - avail, 0)
    swap_total = mem.get('SwapTotal', 0)
    swap_free = mem.get('SwapFree', 0)
    swap_used = max(swap_total - swap_free, 0)
    swap_pct = round((swap_used / swap_total) * 100, 2) if swap_total else 0.0
    warn_swap = float(params.get('warn_swap_percent', 40))
    level = 'WARN' if swap_pct >= warn_swap else 'OK'
    return {
        'level': level,
        'summary': f'RAM used={used//1024}MB/{total//1024}MB, swap={swap_pct}% used',
        'metrics': {
            'ram_mb': {'total': total // 1024, 'used': used // 1024, 'free': avail // 1024, 'cache': mem.get('Cached', 0) // 1024},
            'swap_mb': {'total': swap_total // 1024, 'used': swap_used // 1024, 'free': swap_free // 1024, 'used_percent': swap_pct},
        },
    }


def _parse_df(output: str, inode: bool = False) -> list[dict]:
    lines = [x for x in output.strip().splitlines() if x.strip()]
    rows = []
    for line in lines[1:]:
        parts = line.split()
        if len(parts) < 6:
            continue
        usage = parts[4] if not inode else parts[4]
        rows.append({'filesystem': parts[0], 'usage_percent': int(usage.rstrip('%')), 'mount': parts[5]})
    return rows


def check_disk_advanced(params: dict) -> dict:
    threshold = int(params.get('warn_percent', 85))
    disk = safe_run(['df', '-P'])
    inode = safe_run(['df', '-Pi'])
    disk_rows = _parse_df(disk.stdout)
    inode_rows = _parse_df(inode.stdout, inode=True)
    inode_map = {x['mount']: x['usage_percent'] for x in inode_rows}
    warn_mounts = []
    for row in disk_rows:
        row['inode_percent'] = inode_map.get(row['mount'], 0)
        if row['usage_percent'] >= threshold or row['inode_percent'] >= threshold:
            warn_mounts.append(row)
    level = 'CRIT' if any(m['usage_percent'] >= 90 for m in warn_mounts) else ('WARN' if warn_mounts else 'OK')
    return {'level': level, 'summary': f'Mount warnings={len(warn_mounts)} threshold={threshold}%', 'metrics': {'mounts': disk_rows, 'warning_mounts': warn_mounts}}


def check_processes_top(params: dict) -> dict:
    top_n = int(params.get('top_n', 5))
    by_cpu = safe_run(['ps', '-eo', 'pid,comm,%cpu,%mem', '--sort=-%cpu']).stdout.splitlines()[1 : top_n + 1]
    by_mem = safe_run(['ps', '-eo', 'pid,comm,%cpu,%mem', '--sort=-%mem']).stdout.splitlines()[1 : top_n + 1]
    return {'level': 'OK', 'summary': f'Top {top_n} processes collected by CPU and RAM', 'metrics': {'top_cpu': by_cpu, 'top_ram': by_mem}}


def check_uptime_reboot(_: dict) -> dict:
    uptime = safe_run(['uptime', '-p']).stdout.strip()
    reboot = safe_run(['who', '-b']).stdout.strip()
    return {'level': 'OK', 'summary': f'{uptime}; {reboot}', 'metrics': {'uptime': uptime, 'last_reboot': reboot}}


def check_network_reachability(params: dict) -> dict:
    host = params.get('host', '8.8.8.8')
    port = int(params.get('port', 443))
    ping_path = shutil.which('ping')
    if ping_path:
        p = safe_run([ping_path, '-c', '1', '-W', '1', host], timeout=3)
        if p.returncode == 0:
            return {'level': 'OK', 'summary': f'{host} reachable via ping', 'metrics': {'method': 'ping', 'host': host}}
    started = time.perf_counter()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(float(params.get('timeout', 2)))
    code = sock.connect_ex((host, port))
    sock.close()
    ms = round((time.perf_counter() - started) * 1000, 2)
    level = 'OK' if code == 0 else 'CRIT'
    return {'level': level, 'summary': f'{host}:{port} tcp connect code={code}, latency={ms}ms', 'metrics': {'method': 'tcp', 'latency_ms': ms, 'code': code}}


def check_ports_latency(params: dict) -> dict:
    host = params.get('host', '127.0.0.1')
    ports = params.get('ports', [22, 80, 443])
    timeout = float(params.get('timeout', 1.5))
    rows = []
    for port in ports:
        started = time.perf_counter()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        code = sock.connect_ex((host, int(port)))
        sock.close()
        rows.append({'port': int(port), 'open': code == 0, 'latency_ms': round((time.perf_counter() - started) * 1000, 2)})
    return {'level': 'OK', 'summary': f'Checked {len(rows)} ports on {host}', 'metrics': {'host': host, 'ports': rows}}


def check_dns(params: dict) -> dict:
    domains = params.get('domains', ['localhost', 'example.com'])
    resolved = []
    for domain in domains:
        addrs = sorted({info[4][0] for info in socket.getaddrinfo(domain, None, socket.AF_INET)})
        resolved.append({'domain': domain, 'a_records': addrs})
    return {'level': 'OK', 'summary': f'Resolved {len(resolved)} domain(s)', 'metrics': {'records': resolved}}


def check_traceroute_basic(params: dict) -> dict:
    host = params.get('host', '8.8.8.8')
    hops = str(params.get('max_hops', 8))
    timeout = str(params.get('timeout', 1))
    trace = shutil.which('traceroute')
    if not trace:
        return {'level': 'WARN', 'summary': 'traceroute binary missing', 'metrics': {'host': host, 'hops': []}}
    out = safe_run([trace, '-m', hops, '-w', timeout, host], timeout=15)
    return {'level': 'OK', 'summary': f'Traceroute to {host}', 'metrics': {'output': out.stdout.splitlines()[:20]}}


def check_services_status(params: dict) -> dict:
    services = params.get('services', ['nginx', 'docker'])
    if not shutil.which('systemctl'):
        return {'level': 'WARN', 'summary': 'systemctl not available', 'metrics': {'services': []}}
    rows = []
    for svc in services:
        active = safe_run(['systemctl', 'is-active', svc]).stdout.strip() or 'unknown'
        enabled = safe_run(['systemctl', 'is-enabled', svc]).stdout.strip() or 'unknown'
        rows.append({'service': svc, 'active': active, 'enabled': enabled})
    level = 'WARN' if any(r['active'] not in {'active'} for r in rows) else 'OK'
    return {'level': level, 'summary': f'Services checked={len(rows)}', 'metrics': {'services': rows}}


def check_http_endpoint(params: dict) -> dict:
    import httpx

    url = params.get('url', 'https://example.com')
    verify_tls = bool(params.get('verify_tls', True))
    timeout = float(params.get('timeout', 5))
    started = time.perf_counter()
    with httpx.Client(timeout=timeout, verify=verify_tls) as client:
        resp = client.get(url)
    ms = round((time.perf_counter() - started) * 1000, 2)
    level = 'CRIT' if resp.status_code >= 500 else ('WARN' if resp.status_code >= 400 else 'OK')
    return {'level': level, 'summary': f'HTTP {resp.status_code} in {ms}ms', 'metrics': {'url': url, 'status_code': resp.status_code, 'response_time_ms': ms}}


def check_database_connectivity(params: dict) -> dict:
    checks = [
        ('postgres', params.get('postgres_host', '127.0.0.1'), int(params.get('postgres_port', 5432))),
        ('redis', params.get('redis_host', '127.0.0.1'), int(params.get('redis_port', 6379))),
    ]
    rows = []
    for name, host, port in checks:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(float(params.get('timeout', 1.5)))
        code = sock.connect_ex((host, port))
        sock.close()
        rows.append({'service': name, 'host': host, 'port': port, 'ok': code == 0, 'code': code})
    level = 'CRIT' if any(not x['ok'] for x in rows) else 'OK'
    return {'level': level, 'summary': 'DB TCP checks completed', 'metrics': {'checks': rows}}


def _open_ports() -> list[int]:
    ss = shutil.which('ss')
    if not ss:
        return []
    out = safe_run([ss, '-tuln']).stdout.splitlines()
    ports = set()
    for row in out:
        parts = row.split()
        if len(parts) < 5 or ':' not in parts[4]:
            continue
        try:
            ports.add(int(parts[4].rsplit(':', 1)[1]))
        except ValueError:
            continue
    return sorted(ports)


def check_security_baseline(params: dict) -> dict:
    open_ports = _open_ports()
    danger = {int(x) for x in params.get('dangerous_ports', [23, 445, 3389])}
    flagged = sorted([p for p in open_ports if p in danger])
    sudo_ok = shutil.which('sudo') is not None and safe_run(['sudo', '-n', 'true']).returncode == 0
    scan_roots = [Path.cwd(), Path.home()]
    sensitive_patterns = {'.env', 'config.yml', 'config.yaml', 'secrets.yml'}
    found = []
    for root in scan_roots:
        for current, dirs, files in os.walk(root):
            depth = len(Path(current).parts) - len(root.parts)
            if depth > 3:
                dirs[:] = []
                continue
            for file_name in files:
                if file_name in sensitive_patterns:
                    found.append(str(Path(current) / file_name))
            if len(found) >= 20:
                break
        if len(found) >= 20:
            break
    level = 'WARN' if flagged else 'OK'
    return {
        'level': level,
        'summary': f'Open ports={len(open_ports)}, dangerous={flagged or "none"}',
        'metrics': {'open_ports': open_ports, 'dangerous_open_ports': flagged, 'has_passwordless_sudo': sudo_ok, 'sensitive_files_found': found},
    }


def _snapshot_payload() -> dict:
    return {
        'created_at': datetime.now(timezone.utc).isoformat(),
        'cpu': check_cpu_advanced({})['metrics'],
        'memory': check_memory_advanced({})['metrics'],
        'disk': check_disk_advanced({})['metrics'],
        'open_ports': _open_ports(),
    }


def system_snapshot(params: dict) -> dict:
    base = Path(params.get('snapshot_dir', str(Path.home() / '.agent' / 'snapshots')))
    base.mkdir(parents=True, exist_ok=True)
    payload = _snapshot_payload()
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    path = base / f'snapshot-{stamp}.json'
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding='utf-8')
    (base / 'latest.json').write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding='utf-8')
    return {'level': 'OK', 'summary': f'Snapshot saved to {path.name}', 'metrics': payload}


def system_snapshot_diff(params: dict) -> dict:
    base = Path(params.get('snapshot_dir', str(Path.home() / '.agent' / 'snapshots')))
    base.mkdir(parents=True, exist_ok=True)
    files = sorted(base.glob('snapshot-*.json'))
    current = _snapshot_payload()
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    (base / f'snapshot-{stamp}.json').write_text(json.dumps(current, ensure_ascii=False, indent=2), encoding='utf-8')
    if not files:
        return {'level': 'WARN', 'summary': 'Not enough snapshots for diff (created first snapshot)', 'metrics': {'current': current}}
    previous = json.loads(files[-1].read_text(encoding='utf-8'))
    prev_load = previous.get('cpu', {}).get('load_avg', {}).get('1m', 0)
    cur_load = current.get('cpu', {}).get('load_avg', {}).get('1m', 0)
    prev_ports = set(previous.get('open_ports', []))
    cur_ports = set(current.get('open_ports', []))
    prev_root = next((m for m in previous.get('disk', {}).get('mounts', []) if m.get('mount') == '/'), {})
    cur_root = next((m for m in current.get('disk', {}).get('mounts', []) if m.get('mount') == '/'), {})
    diff = {
        'load_delta_1m': round(cur_load - prev_load, 2),
        'new_open_ports': sorted(cur_ports - prev_ports),
        'removed_open_ports': sorted(prev_ports - cur_ports),
        'root_usage_delta': cur_root.get('usage_percent', 0) - prev_root.get('usage_percent', 0),
    }
    risk = []
    if diff['load_delta_1m'] > 1:
        risk.append('CPU load increased')
    if diff['new_open_ports']:
        risk.append('New open ports detected')
    if diff['root_usage_delta'] > 5:
        risk.append('Disk usage growth >5% on /')
    level = 'WARN' if risk else 'OK'
    return {'level': level, 'summary': 'Snapshot diff calculated', 'metrics': {'diff': diff, 'risk_summary': risk}}


def check_logs_keywords(params: dict) -> dict:
    paths = params.get('paths', ['/var/log/syslog', '/var/log/messages'])
    limit = int(params.get('line_limit', 40))
    needle = re.compile(r'(error|failed)', re.IGNORECASE)
    hits = []
    for path in paths:
        p = Path(path)
        if not p.exists() or not p.is_file():
            continue
        try:
            for line in p.read_text(errors='ignore').splitlines()[-2000:]:
                if needle.search(line):
                    hits.append(f'{p.name}: {line[:200]}')
                    if len(hits) >= limit:
                        break
        except Exception:
            continue
        if len(hits) >= limit:
            break
    return {'level': 'WARN' if hits else 'OK', 'summary': f'Keyword hits={len(hits)}', 'metrics': {'hits': hits, 'line_limit': limit}}


def check_paths_sizes(params: dict) -> dict:
    paths = params.get('paths', ['/tmp'])
    rows = []
    for raw in paths:
        p = Path(raw)
        if not p.exists():
            rows.append({'path': str(p), 'exists': False, 'size': None})
            continue
        if p.is_file():
            rows.append({'path': str(p), 'exists': True, 'size': p.stat().st_size})
        else:
            out = safe_run(['du', '-sh', str(p)], timeout=8).stdout.strip().split()[0]
            rows.append({'path': str(p), 'exists': True, 'size': out})
    return {'level': 'OK', 'summary': f'Paths checked={len(rows)}', 'metrics': {'paths': rows}}


def parse_task_params(task: dict) -> dict:
    command = task.get('command')
    if isinstance(command, str) and command.strip().startswith('{'):
        try:
            data = json.loads(command)
            if isinstance(data, dict):
                return data
        except json.JSONDecodeError:
            return {}
    return task.get('params', {}) if isinstance(task.get('params'), dict) else {}


def execute_task(task_type: str, params: dict) -> dict:
    handlers = {
        'check_cpu_advanced': check_cpu_advanced,
        'check_memory_advanced': check_memory_advanced,
        'check_disk_advanced': check_disk_advanced,
        'check_processes_top': check_processes_top,
        'check_uptime_reboot': check_uptime_reboot,
        'check_network_reachability': check_network_reachability,
        'check_ports_latency': check_ports_latency,
        'check_dns': check_dns,
        'check_traceroute_basic': check_traceroute_basic,
        'check_services_status': check_services_status,
        'check_http_endpoint': check_http_endpoint,
        'check_database_connectivity': check_database_connectivity,
        'check_security_baseline': check_security_baseline,
        'system_snapshot': system_snapshot,
        'system_snapshot_diff': system_snapshot_diff,
        'check_logs_keywords': check_logs_keywords,
        'check_paths_sizes': check_paths_sizes,
    }
    if task_type not in handlers:
        raise KeyError('unsupported task type')
    return handlers[task_type](params)
