import asyncio
import re

import pytest
from nats_nsc import common, nk

pytest_plugins = ('pytest_asyncio',)


@pytest.mark.asyncio
async def test_verify_binary_ok():
    assert await nk.verify_binary('ls')


@pytest.mark.asyncio
async def test_verify_binary_no():
    assert not await nk.verify_binary('no-one-would-name-a-binary-like-that')


@pytest.mark.asyncio
async def test_get_version():
    version_re = re.compile(r'^v\d+\.\d+\.\d+(_[0-9a-f]*)?$')
    version = await nk.v()
    assert version_re.match(version)


@pytest.mark.asyncio
async def test_gen_key():
    key = await nk.gen(common.KeyType.ACCOUNT)
    assert key.startswith('SA') and len(key) == 58


@pytest.mark.asyncio
async def test_pubout():
    pub_key = await nk.pubout('SAAMMEC7S4PGKJZKYJ4QMAB7W73MLECN6BOZPORUZJJXJFFP6QNH3LZD5I')
    assert pub_key == 'AC57TYTG7ZA4RG2ZOJQS2XFAQ3YY2PFY7IYE6TMRSCVTR6XYNHPK65XV'
