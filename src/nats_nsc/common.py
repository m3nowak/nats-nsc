import asyncio
import os
import typing as ty
from dataclasses import dataclass
from enum import Enum

import jwt


def decode_jwt_payload(jwt_token: str) -> dict:
    '''Decode JWT payload.'''
    try:
        return jwt.decode(jwt_token, options={"verify_signature": False})
    except Exception:
        raise ValueError("Invalid JWT")


def key_subpath(pub_key: str) -> str:
    '''Get key subpath from public key.'''
    return os.path.join('keys', pub_key[:1], pub_key[1:3], f'{pub_key}.nk')


async def delete_file(file_path: str):
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, os.remove, file_path)


@dataclass
class Operator():
    name: str
    jwt_path: str
    pub_key: str
    jwt_payload: ty.Dict[str, ty.Any]


@dataclass
class Account():
    name: str
    operator_name: str
    jwt_path: str
    pub_key: str
    has_priv_key: bool


class Credential():
    def __init__(self, payload: str) -> None:
        self._payload = payload

    @property
    def payload(self) -> str:
        return self._payload

    @property
    def jwt(self) -> dict:
        payload_splitted = self._payload.split('\n')
        jwt_line_start = payload_splitted.index('-----BEGIN NATS USER JWT-----')
        jwt_line_end = payload_splitted.index('------END NATS USER JWT------')
        return decode_jwt_payload('\n'.join(payload_splitted[jwt_line_start+1:jwt_line_end]))

    @property
    def nkey(self) -> str:
        payload_splitted = self._payload.split('\n')
        nkey_line_start = payload_splitted.index('-----BEGIN USER NKEY SEED-----')
        nkey_line_end = payload_splitted.index('------END USER NKEY SEED------')
        return '\n'.join(payload_splitted[nkey_line_start+1:nkey_line_end])


class KeyType(Enum):

    USER = 'user'
    ACCOUNT = 'account'
    OPERATOR = 'operator'
