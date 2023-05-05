import base64
import json
import os
import shutil
import tempfile
import typing
from dataclasses import dataclass

from nats_nsc import nsc_utils


_DEFAULT_NSC_PATH = "nsc"

@dataclass
class Operator():
    name: str
    jwt_path: str
    pub_key: str
    jwt_payload: typing.Dict[str, typing.Any]

@dataclass
class Account():
    name: str
    jwt_path: str
    pub_key: str
    has_priv_key: bool

class Credential():
    def __init__(self, payload:str) -> None:
        self._payload = payload
    
    @property
    def payload(self) -> str:
        return self._payload
    
    @property
    def jwt(self) -> str:
        payload_splitted = self._payload.split('\n')
        jwt_line_start = payload_splitted.index('-----BEGIN NATS ACCOUNT JWT-----')
        jwt_line_end = payload_splitted.index('-----END NATS ACCOUNT JWT-----')
        return '\n'.join(payload_splitted[jwt_line_start+1:jwt_line_end])

    @property
    def nkey(self) -> str:
        payload_splitted = self._payload.split('\n')
        nkey_line_start = payload_splitted.index('-----BEGIN USER NKEY SEED-----')
        nkey_line_end = payload_splitted.index('-----END USER NKEY SEED-----')
        return '\n'.join(payload_splitted[nkey_line_start+1:nkey_line_end])

class Context():
    '''Base context for nsc-py, including working directory and nsc binary path.'''

    def __init__(self, nsc_path: typing.Optional[str] = None):
        self._nsc_path = nsc_path or _DEFAULT_NSC_PATH
        if not nsc_utils.verify_binary(self._nsc_path):
            if nsc_path is None:
                raise ValueError("nsc binary not found in PATH")
            else:
                raise ValueError(f"Invalid nsc binary path: {self._nsc_path}")
        self.work_dir = tempfile.mkdtemp(prefix='nsc-py-')
        self.operators = {}
        self.accounts = {}

    @classmethod
    def _decode_jwt_payload(cls, jwt: str) -> dict:
        '''Decode JWT payload.'''
        try:
            return json.loads(base64.b64decode(jwt.split('.')[1]))
        except Exception:
            raise ValueError("Invalid JWT")
    
    def add_operator(self, jwt: str) -> Operator:
        payload = self._decode_jwt_payload(jwt)
        if payload['nats']['type'] != 'operator':
            raise ValueError("Invalid JWT type")
        nsc_utils.load_operator(self._nsc_path, self.work_dir, jwt)
        op_name = payload['name']
        operator = Operator(
            name=op_name,
            jwt_path=os.path.join(self.work_dir, f"{op_name}/{op_name}.jwt"),
            pub_key=payload['sub'],
            jwt_payload=payload
        )
        self.operators[op_name] = operator
        return operator

    def add_account(self, jwt: str, priv_key: str) -> Account:
        payload = self._decode_jwt_payload(jwt)
        if payload['nats']['type'] != 'account':
            raise ValueError("Invalid JWT type")
        if priv_key is not None:
            nsc_utils.load_key(self._nsc_path, self.work_dir, priv_key)
        acc_name = payload['name']
        nsc_utils.load_account(self.work_dir, jwt, acc_name)
        account = Account(
            name=acc_name,
            jwt_path=os.path.join(self.work_dir, f"accounts/{acc_name}/{acc_name}.jwt"),
            pub_key=payload['sub'],
            has_priv_key=priv_key is not None
        )
        self.accounts[acc_name] = account
        return account


    def __del__(self):
        shutil.rmtree(self.work_dir, ignore_errors=True)
