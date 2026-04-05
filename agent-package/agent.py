import argparse
import base64
import json
import logging
import os
import platform
import shlex
import socket
import subprocess
import sys
import shutil
import time
import uuid
from pathlib import Path

import httpx
import nacl.encoding
import nacl.signing

from diagnostics import execute_task, format_result, parse_task_params, truncate_text

CONFIG_DIR = Path(os.getenv('AGENT_CONFIG_DIR', '/agent-data'))
PRIVATE_KEY_PATH = CONFIG_DIR / 'private.key'
PUBLIC_KEY_PATH = CONFIG_DIR / 'public.key'
CONFIG_PATH = CONFIG_DIR / 'config.json'
DEFAULT_INTERVAL = 5
MAX_INTERVAL = 10
MIN_INTERVAL = 5
MAX_BACKOFF_SECONDS = 60
SAFE_EXEC_DIRS = {'/bin', '/usr/bin', '/usr/sbin', '/sbin'}

logger = logging.getLogger('kyss-agent')


class ReRegisterRequired(Exception):
    pass


def configure_logging(level: str) -> None:
    numeric_level = getattr(logging, level.upper(), logging.INFO)
    logging.basicConfig(
        level=numeric_level,
        stream=sys.stdout,
        format='%(asctime)s | %(levelname)s | %(name)s | %(message)s',
    )
    if numeric_level > logging.DEBUG:
        logging.getLogger('httpx').setLevel(logging.WARNING)
        logging.getLogger('httpcore').setLevel(logging.WARNING)


def ensure_keys() -> tuple[str, str]:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    if PRIVATE_KEY_PATH.exists() and PUBLIC_KEY_PATH.exists():
        logger.debug('Using existing Ed25519 key pair from %s', CONFIG_DIR)
        return PRIVATE_KEY_PATH.read_text().strip(), PUBLIC_KEY_PATH.read_text().strip()

    signing_key = nacl.signing.SigningKey.generate()
    verify_key = signing_key.verify_key
    private_b64 = signing_key.encode(encoder=nacl.encoding.Base64Encoder).decode()
    public_b64 = verify_key.encode(encoder=nacl.encoding.Base64Encoder).decode()
    PRIVATE_KEY_PATH.write_text(private_b64)
    PUBLIC_KEY_PATH.write_text(public_b64)
    os.chmod(PRIVATE_KEY_PATH, 0o600)
    logger.info('Generated new Ed25519 key pair in %s', CONFIG_DIR)
    return private_b64, public_b64


def sign_payload(private_key_b64: str, payload: dict, timestamp: int) -> str:
    key = nacl.signing.SigningKey(private_key_b64, encoder=nacl.encoding.Base64Encoder)
    msg = json.dumps(payload, sort_keys=True, separators=(',', ':')) + f'*{timestamp}'
    sig = key.sign(msg.encode()).signature
    return base64.b64encode(sig).decode()


def get_local_ips() -> list[str]:
    ips = set()
    hostname = socket.gethostname()
    try:
        for info in socket.getaddrinfo(hostname, None):
            addr = info[4][0]
            if ':' not in addr:
                ips.add(addr)
    except Exception as exc:
        logger.debug('Failed to resolve local IP addresses: %s', exc)
    return sorted(list(ips))




def get_safe_executable(binary_name: str) -> str:
    executable = shutil.which(binary_name)
    if not executable:
        raise FileNotFoundError(f'binary not found: {binary_name}')
    if os.path.dirname(executable) not in SAFE_EXEC_DIRS:
        raise PermissionError(f'unsafe binary path: {executable}')
    return executable

def build_allowed_command_map(raw_allowed: str) -> dict[str, list[str]]:
    allowed_map: dict[str, list[str]] = {}
    for cmd in [item.strip() for item in raw_allowed.split(',') if item.strip()]:
        parts = shlex.split(cmd)
        if not parts:
            continue
        executable = shutil.which(parts[0])
        if not executable:
            logger.warning('Allowed command skipped (binary not found): %s', cmd)
            continue
        if os.path.dirname(executable) not in SAFE_EXEC_DIRS:
            logger.warning('Allowed command skipped (unsafe binary path): %s -> %s', cmd, executable)
            continue
        allowed_map[cmd] = [executable, *parts[1:]]
    return allowed_map


def run_task(task: dict, allowed_commands: dict[str, list[str]], timeout_sec: int = 20) -> tuple[str, str, str]:
    task_type = task.get('task_type')
    task_uid = task.get('task_uid', 'unknown')
    logger.info('Processing task task_uid=%s task_type=%s', task_uid, task_type)
    try:
        if task_type == 'check_cpu':
            out = subprocess.check_output([get_safe_executable('uptime')], text=True, timeout=5)
            out = truncate_text(out)
            return 'done', out, out
        if task_type == 'check_ram':
            out = subprocess.check_output([get_safe_executable('free'), '-m'], text=True, timeout=5)
            out = truncate_text(out)
            return 'done', out, out
        if task_type == 'check_disk':
            out = subprocess.check_output([get_safe_executable('df'), '-h'], text=True, timeout=5)
            out = truncate_text(out)
            return 'done', out, out
        if task_type == 'check_ports':
            ports = [22, 80, 443]
            states = []
            for p in ports:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1)
                code = s.connect_ex(('127.0.0.1', p))
                states.append(f'{p}:{"open" if code == 0 else "closed"}')
                s.close()
            result = ', '.join(states)
            result = truncate_text(result)
            return 'done', result, result
        if task_type == 'check_system_info':
            result = {
                'hostname': platform.node(),
                'ip_addresses': get_local_ips(),
                'os_version': platform.platform(),
                'network_interfaces': get_local_ips(),
                'connectivity': 'ok' if socket.gethostbyname('localhost') else 'failed',
            }
            text = truncate_text(json.dumps(result, ensure_ascii=False))
            return 'done', text, text
        if task_type == 'run_command':
            cmd = task.get('command', '')
            args = allowed_commands.get(cmd)
            if not args:
                logger.warning('Rejected command by allowlist: %s', cmd)
                return 'failed', 'команда отклонена whitelist', 'команда отклонена whitelist'
            result = subprocess.run(args, capture_output=True, text=True, timeout=timeout_sec, check=False)
            output = truncate_text(result.stdout + '\n' + result.stderr)
            return ('done' if result.returncode == 0 else 'failed', output, output)

        params = parse_task_params(task)
        diagnostic = execute_task(task_type, params)
        payload = format_result(diagnostic)
        status = 'done' if diagnostic.get('level') != 'CRIT' else 'failed'
        return status, payload, payload
    except KeyError:
        return 'failed', 'неизвестный тип задачи', 'неизвестный тип задачи'
    except Exception as exc:
        logger.exception('Task execution failed task_uid=%s: %s', task_uid, exc)
        msg = truncate_text(f'ошибка выполнения: {exc}')
        return 'failed', msg, msg


def build_envelope(agent_uid: str, private_key: str, payload: dict) -> dict:
    now = int(time.time())
    return {
        'agent_uid': agent_uid,
        'timestamp': now,
        'nonce': str(uuid.uuid4()),
        'payload': payload,
        'signature': sign_payload(private_key, payload, now),
    }


def register(base_url: str, token: str, verify_tls: bool, agent_uid: str | None = None):
    private_key, public_key = ensure_keys()
    payload = {
        'agent_uid': agent_uid or str(uuid.uuid4()),
        'hostname': platform.node() or 'unknown',
        'public_key': public_key,
        'registration_token': token,
    }
    with httpx.Client(timeout=10, verify=verify_tls) as client:
        r = client.post(f'{base_url}/api/agents/register', json=payload)
        r.raise_for_status()
        data = r.json()
    cfg = {
        'base_url': base_url,
        'agent_uid': data['agent_id'],
        'public_key': public_key,
        'agent_token': data['agent_token'],
    }
    CONFIG_PATH.write_text(json.dumps(cfg))
    logger.info('Agent registration complete. agent_uid=%s', data['agent_id'])
    return private_key, cfg


def register_with_retry(base_url: str, token: str, verify_tls: bool, preferred_agent_uid: str | None = None):
    backoff = MIN_INTERVAL
    while True:
        try:
            logger.info('Registering agent on %s', base_url)
            return register(base_url, token, verify_tls, agent_uid=preferred_agent_uid)
        except Exception as exc:
            logger.warning('Registration failed: %s. Retry in %ss', exc, backoff)
            time.sleep(backoff)
            backoff = min(backoff * 2, MAX_BACKOFF_SECONDS)


def load_or_register(base_url: str, token: str, verify_tls: bool):
    private_key, _ = ensure_keys()
    if CONFIG_PATH.exists():
        cfg = json.loads(CONFIG_PATH.read_text())
        logger.info('Loaded existing agent config from %s for agent_uid=%s', CONFIG_PATH, cfg.get('agent_uid'))
        return private_key, cfg
    private_key, cfg = register_with_retry(base_url, token, verify_tls)
    return private_key, cfg


def ensure_status(response: httpx.Response, scope: str) -> None:
    if response.status_code == 401:
        raise ReRegisterRequired(f'{scope}: unauthorized (401)')
    response.raise_for_status()


def loop(base_url: str, agent_uid: str, agent_token: str, private_key: str, public_key: str, interval: int, verify_tls: bool):
    allowed = build_allowed_command_map(os.getenv('ALLOWED_COMMANDS', 'uptime,df -h,free -m'))
    headers = {'Authorization': f'Bearer {agent_token}'}
    sleep_time = max(MIN_INTERVAL, min(interval, MAX_INTERVAL))
    logger.info('Agent loop started. heartbeat_interval=%ss allowed_commands=%s', sleep_time, sorted(allowed))

    while True:
        hb_payload = {
            'hostname': platform.node(),
            'public_key': public_key,
            'ip_addresses': get_local_ips(),
            'os_version': platform.platform(),
            'network_interfaces': get_local_ips(),
        }
        try:
            with httpx.Client(timeout=10, verify=verify_tls, headers=headers) as client:
                hb_response = client.post(f'{base_url}/api/agents/heartbeat', json=build_envelope(agent_uid, private_key, hb_payload))
                ensure_status(hb_response, 'heartbeat')
                task_response = client.post(f'{base_url}/api/agents/tasks/next', json=build_envelope(agent_uid, private_key, hb_payload))
                ensure_status(task_response, 'tasks/next')
                task = task_response.json().get('task')
                if task:
                    status, result, logs = run_task(task, allowed_commands=allowed)
                    task_payload = {'task_uid': task['task_uid'], 'status': status, 'result': result, 'logs': logs}
                    result_response = client.post(
                        f'{base_url}/api/tasks/result',
                        json=build_envelope(agent_uid, private_key, task_payload),
                    )
                    ensure_status(result_response, 'tasks/result')
                    logger.info('Task completed task_uid=%s status=%s', task['task_uid'], status)
        except ReRegisterRequired as exc:
            raise ReRegisterRequired(str(exc)) from exc
        except Exception as exc:
            logger.warning('Agent loop iteration failed: %s', exc)
        time.sleep(sleep_time)


def str_to_bool(value: str) -> bool:
    return value.strip().lower() in {'1', 'true', 'yes', 'on'}


def run_forever(base_url: str, registration_token: str, interval: int, verify_tls: bool):
    private_key, cfg = load_or_register(base_url, registration_token, verify_tls)

    while True:
        try:
            public = PUBLIC_KEY_PATH.read_text().strip()
            loop(base_url, cfg['agent_uid'], cfg['agent_token'], private_key, public, interval, verify_tls)
        except ReRegisterRequired as exc:
            old_uid = cfg.get('agent_uid')
            logger.warning('Need re-register agent (%s). Trying to refresh credentials for agent_uid=%s', exc, old_uid)
            private_key, cfg = register_with_retry(base_url, registration_token, verify_tls, preferred_agent_uid=old_uid)


def main():
    parser = argparse.ArgumentParser(description='KYSSCHECK Agent')
    parser.add_argument('--base-url', default=os.getenv('BASE_URL'))
    parser.add_argument('--registration-token', default=os.getenv('REGISTRATION_TOKEN'))
    parser.add_argument('--interval', type=int, default=int(os.getenv('AGENT_INTERVAL', str(DEFAULT_INTERVAL))))
    parser.add_argument('--log-level', default=os.getenv('LOG_LEVEL', 'INFO'))
    parser.add_argument('--verify-tls', default=os.getenv('VERIFY_TLS', 'true'))
    args = parser.parse_args()

    if not args.base_url or not args.registration_token:
        raise SystemExit('BASE_URL and REGISTRATION_TOKEN are required (via args or env).')

    configure_logging(args.log_level)
    verify_tls = str_to_bool(args.verify_tls)
    if not verify_tls:
        logger.warning('TLS certificate verification is disabled (VERIFY_TLS=false). Use only for local debugging.')
    if args.base_url.startswith('https://') and not verify_tls:
        logger.info('HTTPS is used with VERIFY_TLS=false. For local dev only.')
    if args.base_url.startswith('http://') and verify_tls:
        logger.info('Base URL uses HTTP. TLS verification setting has no effect for plain HTTP.')

    run_forever(args.base_url, args.registration_token, args.interval, verify_tls)


if __name__ == '__main__':
    main()
