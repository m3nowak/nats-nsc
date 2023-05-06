import os
import typing as ty
import tempfile
from datetime import timedelta

from nats_nsc import nsc_utils, common

_DEFAULT_NSC_PATH = "nsc"


class Context():
    '''Base context for nsc-py, including working directory and nsc binary path.'''

    @classmethod
    async def async_factory(cls, nsc_path: ty.Optional[str] = None) -> 'Context':
        '''Create a context asynchronously.'''

        _nsc_path = nsc_path or str(_DEFAULT_NSC_PATH)
        if not await nsc_utils.verify_binary(_nsc_path):
            if nsc_path is None:
                raise ValueError("nsc binary not found in PATH")
            else:
                raise ValueError(f"Invalid nsc binary path: {_nsc_path}")
        work_dir = tempfile.TemporaryDirectory(prefix='nsc-py-')
        ctx = cls(work_dir, _nsc_path)
        return ctx

    def __init__(self, work_dir: tempfile.TemporaryDirectory, nsc_path: str):
        self._nsc_path = nsc_path
        self.work_dir = work_dir
        self.operators = {}
        self.accounts = {}

    async def add_operator(self, jwt_token: str) -> common.Operator:
        payload = common.decode_jwt_payload(jwt_token)
        if payload['nats']['type'] != 'operator':
            raise ValueError("Invalid JWT type")
        await nsc_utils.load_operator(self._nsc_path, self.work_dir.name, jwt_token)
        op_name = payload['name']
        operator = common.Operator(
            name=op_name,
            jwt_path=os.path.join(self.work_dir.name, f"{op_name}/{op_name}.jwt"),
            pub_key=payload['sub'],
            jwt_payload=payload
        )
        self.operators[op_name] = operator
        return operator

    async def add_account(self, jwt_token: str, operator: common.Operator,
                          priv_key: ty.Optional[str] = None) -> common.Account:
        payload = common.decode_jwt_payload(jwt_token)
        if payload['nats']['type'] != 'account':
            raise ValueError("Invalid JWT type")
        if priv_key is not None:
            await nsc_utils.load_key(self._nsc_path, self.work_dir.name, priv_key)
        acc_name = payload['name']
        await nsc_utils.load_account(self.work_dir.name, jwt_token, operator, acc_name)
        account = common.Account(
            name=acc_name,
            operator_name=operator.name,
            jwt_path=os.path.join(self.work_dir.name, f"accounts/{acc_name}/{acc_name}.jwt"),
            pub_key=payload['sub'],
            has_priv_key=priv_key is not None
        )
        self.accounts[acc_name] = account
        return account

    async def create_user(self, user_name: str, account: common.Account,
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
        return await nsc_utils.create_user(self._nsc_path,
                                           self.work_dir.name,
                                           user_name, account,
                                           allow_pub,
                                           allow_pub_response,
                                           allow_pubsub,
                                           allow_sub,
                                           bearer,
                                           deny_pub,
                                           deny_pubsub,
                                           deny_sub,
                                           expiry,
                                           response_ttl,
                                           source_networks,
                                           start,
                                           tag)

    def __del__(self):
        self.work_dir.cleanup()
