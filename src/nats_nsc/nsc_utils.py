import asyncio
import os.path
import shlex
import typing as ty
from datetime import timedelta

import aiofiles

from nats_nsc import common


async def verify_binary(nsc_path: str) -> bool:
    '''Verify if binary is available in PATH.'''
    try:
        proc = await asyncio.create_subprocess_exec(nsc_path, "--version", stdout=asyncio.subprocess.PIPE,
                                                    stderr=asyncio.subprocess.PIPE)
        await proc.wait()
        return True
    except FileNotFoundError:
        return False


async def load_operator(nsc_path: str, nsc_work_dir: str, jwt: str):
    '''Load operator from JWT.'''
    async with aiofiles.tempfile.NamedTemporaryFile() as fle:
        await fle.write(jwt.encode())
        await fle.flush()
        proc = await asyncio.create_subprocess_exec(nsc_path, "-H", nsc_work_dir, 'add',
                                                    'operator', '-u', str(fle.name), stdout=asyncio.subprocess.PIPE,
                                                    stderr=asyncio.subprocess.PIPE)
        await proc.wait()
        await fle.close()


async def load_key(nsc_path: str, nsc_work_dir: str, key: str):
    '''Load key from string.'''
    async with aiofiles.tempfile.TemporaryDirectory() as temp_dir:
        async with aiofiles.tempfile.NamedTemporaryFile(dir=temp_dir, suffix='.nk') as fle:
            key_encoded = key.encode()
            await fle.write(key_encoded)
            await fle.flush()
            await fle.seek(0)
            proc = await asyncio.create_subprocess_exec(nsc_path, "-H", nsc_work_dir, 'import',
                                                        'keys', '--dir', temp_dir, stdout=asyncio.subprocess.PIPE,
                                                        stderr=asyncio.subprocess.PIPE)
            await proc.wait()
            await fle.write(b' ' * len(key_encoded))
            await fle.close()


async def load_account(nsc_work_dir: str, jwt: str, operator: common.Operator, name: str):
    '''Load account from JWT.'''
    account_dir = os.path.join(
        nsc_work_dir, f"{operator.name}/accounts/{name}")
    if not os.path.exists(account_dir):
        os.mkdir(account_dir)
    async with aiofiles.open(os.path.join(account_dir, f"{name}.jwt"), 'w') as fle:
        await fle.write(jwt)
        await fle.close()


def _timedelta_to_nats_duration(td: timedelta) -> str:
    '''Convert timedelta to nats duration string.'''
    return f"{td.days}d{td.seconds // 60}m"


def _timedelta_to_nats_duration_precise(td: timedelta) -> str:
    '''Convert timedelta to precise nats duration string.'''
    return f"{td.days*24*60 + td.seconds}s{td.microseconds//1000}ms"


async def create_user(nsc_path: str, nsc_work_dir: str,
                      user_name: str, account: common.Account,
                      allow_pub: ty.Optional[ty.List[str]] = None,
                      allow_pub_response: ty.Optional[int] = None,
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
                      tag: ty.Optional[ty.List[str]] = None) -> common.Credential:
    '''Create user.'''
    args = [nsc_path, "-H", nsc_work_dir, 'add', 'user', '-a', shlex.quote(account.name), '-n', shlex.quote(
        user_name)]
    if allow_pub_response is not None:
        args.append(f'--allow-pub-response={allow_pub_response}')
    if allow_pub is not None:
        args += ['--allow-pub', shlex.quote(','.join(allow_pub))]
    if allow_pubsub is not None:
        args += ['--allow-pubsub', shlex.quote(','.join(allow_pubsub))]
    if allow_sub is not None:
        args += ['--allow-sub', ','.join(allow_sub)]
    if bearer:
        args += ['--bearer']
    if deny_pub is not None:
        args += ['--deny-pub', shlex.quote(','.join(deny_pub))]
    if deny_pubsub is not None:
        args += ['--deny-pubsub', shlex.quote(','.join(deny_pubsub))]
    if deny_sub is not None:
        args += ['--deny-sub', shlex.quote(','.join(deny_sub))]
    if expiry is not None:
        args += ['--expiry', _timedelta_to_nats_duration(expiry)]
    if response_ttl is not None:
        args += ['--response-ttl',
                 _timedelta_to_nats_duration_precise(response_ttl)]
    if source_networks is not None:
        args += ['--source-networks', shlex.quote(','.join(source_networks))]
    if start is not None:
        args += ['--start', _timedelta_to_nats_duration(start)]
    if tag is not None:
        args += ['--tag', shlex.quote(','.join(tag))]

    process = await asyncio.create_subprocess_exec(*args, stdout=asyncio.subprocess.PIPE,
                                                   stderr=asyncio.subprocess.PIPE)
    # await process.wait()
    _, resp = await process.communicate()
    creds_path = list(
        filter(lambda x: 'generated user creds file' in x, resp.decode().split('\n')))
    if len(creds_path) == 0:
        raise Exception(f'Could not create user {resp}')
    else:
        creds_path = creds_path[0].split('`')[1]
    creds_txt = None
    async with aiofiles.open(creds_path, 'r') as c_file:
        creds_txt = await c_file.read()
    creds = common.Credential(creds_txt)

    await common.delete_file(os.path.join(nsc_work_dir, common.key_subpath(creds.jwt['sub'])))
    await common.delete_file(os.path.join(nsc_work_dir, 'creds', account.operator_name,
                                          account.name, f'{user_name}.creds'))

    return creds
