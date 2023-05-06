'''Adapter for nk utility.'''

import asyncio
import typing as ty

import aiofiles

from . import common

_NK = 'nk'


async def verify_binary(nsc_path: str) -> bool:
    '''Verify if binary is available in PATH.'''
    try:
        proc = await asyncio.create_subprocess_exec(nsc_path, "-v", stdout=asyncio.subprocess.PIPE,
                                                    stderr=asyncio.subprocess.PIPE)
        await proc.wait()
        return True
    except FileNotFoundError:
        return False


async def v(nk_path: ty.Optional[str] = None) -> str:
    '''Get version of nk utility.'''
    if not nk_path:
        nk_path = _NK

    process = await asyncio.create_subprocess_exec(nk_path, '-v', stdout=asyncio.subprocess.PIPE,
                                                   stderr=asyncio.subprocess.PIPE)
    # await process.wait()
    resp, _ = await process.communicate()
    return resp.splitlines()[0].decode().split(' ')[-1]


async def gen(key_type: common.KeyType, nk_path: ty.Optional[str] = None) -> str:
    '''Create private key.'''
    if not nk_path:
        nk_path = _NK

    process = await asyncio.create_subprocess_exec(nk_path, '-gen', key_type.value, stdout=asyncio.subprocess.PIPE,
                                                   stderr=asyncio.subprocess.PIPE)
    await process.wait()
    resp, _ = await process.communicate()
    return resp.decode().strip()


async def pubout(inkey: str, nk_path: ty.Optional[str] = None) -> str:
    '''Get public key from private key.'''
    if not nk_path:
        nk_path = _NK

    async with aiofiles.tempfile.NamedTemporaryFile(suffix='.nk') as fle:
        await fle.write(inkey.encode())
        await fle.flush()
        process = await asyncio.create_subprocess_exec(nk_path, '-pubout', '-inkey', str(fle.name),
                                                       stdout=asyncio.subprocess.PIPE,
                                                       stderr=asyncio.subprocess.PIPE)
        await process.wait()
        resp, _ = await process.communicate()
    return resp.decode().strip()
