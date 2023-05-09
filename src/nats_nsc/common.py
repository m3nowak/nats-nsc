import asyncio
import os
import typing as ty
from datetime import datetime, timedelta
from dataclasses import dataclass
from enum import Enum
import math

import jwt

TTL_SCALE = math.pow(10, 9)


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
class AccountLimits():
    subs: int
    data: int
    payload: int
    imports: int
    exports: int
    wildcards: bool
    conn: int
    leaf: int

@dataclass
class Permissions():
    allow: ty.List[str]
    deny: ty.List[str]

    def as_dict(self) -> ty.Dict[str, ty.List[str]]:
        return {
            'allow': self.allow,
            'deny': self.deny
        }

@dataclass
class UserLimits():
    subs: int
    data: int
    payload: int


class _Auth():
    jwt_payload: ty.Dict[str, ty.Any]

    def __init__(self, jwt_token: str) -> None:
        jwt_payload = decode_jwt_payload(jwt_token)
        if not self._verify_payload(jwt_payload):
            raise ValueError("Invalid JWT type")
        self.jwt_payload = jwt_payload

    @classmethod
    def _verify_payload(cls, payload: ty.Dict[str, ty.Any]) -> bool:
        raise NotImplementedError

    @property
    def jwt_id(self) -> str:
        return self.jwt_payload['jti']

    @property
    def name(self) -> str:
        return self.jwt_payload['name']
    
    @property
    def pub_key(self) -> str:
        return self.jwt_payload['sub']
    
    @property
    def subject(self) -> str:
        return self.pub_key

    @property
    def nats_props(self) -> ty.Dict[str, ty.Any]:
        return self.jwt_payload['nats']
    
    @property
    def issuer(self) -> str:
        return self.jwt_payload['iss']
    
    @property
    def issued_at(self) -> datetime:
        return datetime.utcfromtimestamp(self.jwt_payload['iat'])


class Operator(_Auth):
    @classmethod
    def _verify_payload(cls, payload: ty.Dict[str, ty.Any]) -> bool:
        return payload['nats']['type'] == 'operator'


class Account(_Auth):
    priv_key: ty.Optional[str] = None

    def __init__(self, jwt_token: str, priv_key: ty.Optional[str] = None) -> None:
        super().__init__(jwt_token)
        self.priv_key = priv_key

    @classmethod
    def _verify_payload(cls, payload: ty.Dict[str, ty.Any]) -> bool:
        return payload['nats']['type'] == 'account'
    
    @property
    def limits(self) -> AccountLimits:
        return AccountLimits(**self.jwt_payload['nats']['limits'])
    
    @property
    def sub_permissions(self) -> Permissions:
        ps_dct = self.jwt_payload['nats']['default_permissions']['sub']
        return Permissions(allow=ps_dct['allow'] if 'allow' in ps_dct else [],
                           deny=ps_dct['deny'] if 'deny' in ps_dct else [])
    
    @property
    def pub_permissions(self) -> Permissions:
        ps_dct = self.jwt_payload['nats']['default_permissions']['pub']
        return Permissions(allow=ps_dct['allow'] if 'allow' in ps_dct else [],
                           deny=ps_dct['deny'] if 'deny' in ps_dct else [])
    
    @property
    def has_key(self) -> bool:
        return self.priv_key is not None

class User(_Auth):
    full_jwt: str

    def __init__(self, jwt_token: str) -> None:
        self.full_jwt = jwt_token
        super().__init__(jwt_token)
        

    @classmethod
    def _verify_payload(cls, payload: ty.Dict[str, ty.Any]) -> bool:
        return payload['nats']['type'] == 'user'

    @property
    def limits(self) -> UserLimits:
        nats_dict = self.jwt_payload['nats']
        return UserLimits(subs=nats_dict['sub'], data=nats_dict['data'], payload=nats_dict['payload'])
    
    @property
    def sub_permissions(self) -> Permissions:
        return Permissions(**self.jwt_payload['nats']['sub'])
    
    @property
    def pub_permissions(self) -> Permissions:
        return Permissions(**self.jwt_payload['nats']['pub'])

    @property
    def src_networks(self) -> ty.Optional[ty.List[str]]:
        return self.jwt_payload['nats']['src'] if 'src' in self.jwt_payload['nats'] else None
    
    @property
    def bearer(self) -> bool:
        return self.jwt_payload['nats']['bearer_token'] if 'bearer_token' in self.jwt_payload['bearer_token'] else False

    @property
    def resp_ttl(self) -> timedelta:
        seconds = self.jwt_payload['nats']['resp']['ttl'] / TTL_SCALE if 'resp' in self.jwt_payload['nats'] else 1.0
        return timedelta(seconds=seconds)

    @property
    def max_resp(self) -> int:
        return self.jwt_payload['nats']['resp']['max'] if 'resp' in self.jwt_payload['nats'] else 1

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


def _timedelta_to_nats_duration(td: timedelta) -> str:
    '''Convert timedelta to nats duration string.'''
    return f"{td.days}d{td.seconds // 60}m"


def _timedelta_to_nats_duration_precise(td: timedelta) -> str:
    '''Convert timedelta to precise nats duration string.'''
    return f"{td.days*24*60 + td.seconds}s{td.microseconds//1000}ms"
