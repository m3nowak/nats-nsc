import os.path
import shlex
import subprocess
import tempfile
import typing as ty
from datetime import timedelta


def verify_binary(nsc_path: str) -> bool:
    '''Verify if binary is available in PATH.'''
    try:
        subprocess.check_output(
            [nsc_path, "--version"], stderr=subprocess.STDOUT)
        return True
    except FileNotFoundError:
        return False


def load_operator(nsc_path: str, nsc_work_dir: str, jwt: str):
    '''Load operator from JWT.'''
    fle = tempfile.NamedTemporaryFile()
    fle.write(jwt.encode())
    fle.close()
    subprocess.check_output([nsc_path, "-H", nsc_work_dir, 'add',
                            'operator', '-u', fle.name], stderr=subprocess.STDOUT)
    del fle


def load_key(nsc_path: str, nsc_work_dir: str, key: str):
    '''Load key from string.'''
    temp_dir = tempfile.TemporaryDirectory()
    fle = tempfile.NamedTemporaryFile(dir=temp_dir.name, suffix='.nk')
    key_encoded = key.encode()
    fle.write(key_encoded)
    fle.flush()
    fle.seek(0)
    subprocess.check_output([nsc_path, "-H", nsc_work_dir, 'import',
                            'keys', '--dir', temp_dir.name], stderr=subprocess.STDOUT)
    fle.write(b' ' * len(key_encoded))
    fle.close()
    del fle


def load_account(nsc_work_dir: str, jwt: str, name: str):
    '''Load account from JWT.'''
    account_dir = os.path.join(nsc_work_dir, f"accounts/{name}")
    if not os.path.exists(account_dir):
        os.mkdir(account_dir)
    fle = open(os.path.join(account_dir, f"{name}.jwt"), 'w')
    fle.write(jwt)
    fle.close()


def timedelta_to_nats_duration(td: timedelta) -> str:
    '''Convert timedelta to nats duration string.'''
    return f"{td.days}d{td.seconds // 60}m"


def timedelta_to_nats_duration_precise(td: timedelta) -> str:
    '''Convert timedelta to precise nats duration string.'''
    return f"{td.days*24*60 + td.seconds}s{td.microseconds//1000}ms"


def create_user(nsc_path: str, nsc_work_dir: str,
                user_name: str, account_name: str,
                allow_pub: ty.Optional[ty.List[str]] = None,
                allow_pub_response: int = 1,
                allow_pubsub: ty.Optional[ty.List[str]] = None,
                allow_sub: ty.Optional[ty.List[str]] = None,
                bearer: bool = False,
                deny_pub: ty.Optional[ty.List[str]] = None,
                deny_pubsub: ty.Optional[ty.List[str]] = None,
                deny_sub: ty.Optional[ty.List[str]] = None,
                expiry: ty.Optional[timedelta] = None,
                response_ttl: ty.Optional[timedelta] = None,
                source_networks: ty.Optional[ty.List[str]] = None,
                start: ty.Optional[timedelta] = None,
                tag: ty.Optional[ty.List[str]] = None) -> str:
    '''Create user.'''
    args = [nsc_path, "-H", nsc_work_dir, '-a', shlex.quote(account_name), '-n', shlex.quote(
        user_name), '-allow-pub-response', str(allow_pub_response)]
    if allow_pub is not None:
        args += ['--allow-pub', shlex.quote(','.join(allow_pub))]
    if allow_pubsub is not None:
        args += ['--allow-pubsub', shlex.quote(','.join(allow_pubsub))]
    if allow_sub is not None:
        args += ['--allow-sub', shlex.quote(','.join(allow_sub))]
    if bearer:
        args += ['--bearer']
    if deny_pub is not None:
        args += ['--deny-pub', shlex.quote(','.join(deny_pub))]
    if deny_pubsub is not None:
        args += ['--deny-pubsub', shlex.quote(','.join(deny_pubsub))]
    if deny_sub is not None:
        args += ['--deny-sub', shlex.quote(','.join(deny_sub))]
    if expiry is not None:
        args += ['--expiry', timedelta_to_nats_duration(expiry)]
    if response_ttl is not None:
        args += ['--response-ttl',
                 timedelta_to_nats_duration_precise(response_ttl)]
    if source_networks is not None:
        args += ['--source-networks', shlex.quote(','.join(source_networks))]
    if start is not None:
        args += ['--start', timedelta_to_nats_duration(start)]
    if tag is not None:
        args += ['--tag', shlex.quote(','.join(tag))]

    resp = subprocess.check_output(args, stderr=subprocess.STDOUT).decode()
    creds_path = list(
        filter(lambda x: 'generated user creds file' in x, resp.split('\n')))
    if len(creds_path) == 0:
        raise Exception(f'Could not create user {resp}')
    else:
        creds_path = creds_path[0].split('`')[1]

    return open(creds_path, 'r').read()
