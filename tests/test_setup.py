import nats_nsc
import pytest
import asyncio

pytest_plugins = ('pytest_asyncio',)


OP_JWT = open('tests/nsc_workdir/nats-nsc-testing/nats-nsc-testing.jwt', 'r').read()
AC_JWT = open('tests/nsc_workdir/nats-nsc-testing/accounts/nats-nsc-testing/nats-nsc-testing.jwt', 'r').read()
AC_KEY = open('tests/nsc_workdir/keys/A/DD/ADDMOZZDAAU5LB4UML6N2QLIVCGXLEIYZZ5TT4YJCUKQT2FQIE25BZAG.nk', 'r').read()


@pytest.mark.asyncio
async def test_basic_setup():
    ctx = await nats_nsc.Context.async_factory()
    operator = await ctx.add_operator(OP_JWT)
    await ctx.add_account(AC_JWT, operator)


@pytest.mark.asyncio
async def test_key_setup():
    ctx = await nats_nsc.Context.async_factory()
    operator = await ctx.add_operator(OP_JWT)
    await ctx.add_account(AC_JWT, operator, AC_KEY)


@pytest.mark.asyncio
async def test_user_creation():
    ctx = await nats_nsc.Context.async_factory()
    operator = await ctx.add_operator(OP_JWT)
    account = await ctx.add_account(AC_JWT, operator, AC_KEY)
    user = await ctx.create_user('test_user', account)
    assert user.jwt['nats']['type'] == 'user'
    assert user.nkey.startswith('SU')


@pytest.mark.asyncio
async def test_hello_world():
    # test async communication sanity
    process = await asyncio.create_subprocess_shell('echo Hello World', stdout=asyncio.subprocess.PIPE)
    data, _ = await process.communicate()
    assert data == b'Hello World\n'
