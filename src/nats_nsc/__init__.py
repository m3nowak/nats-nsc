"""User token creation for NATS"""

import os
import typing as ty
from datetime import datetime, timedelta
from dataclasses import dataclass, fields
from enum import Enum

import jwt

TTL_SCALE = 1_000_000_000


def _decode_jwt_payload(jwt_token: str) -> dict:
    '''Decode JWT payload.'''
    try:
        return jwt.decode(jwt_token, options={"verify_signature": False})
    except Exception:
        raise ValueError("Invalid JWT")


def _key_subpath(pub_key: str) -> str:
    '''Get key subpath from public key.'''
    return os.path.join('keys', pub_key[:1], pub_key[1:3], f'{pub_key}.nk')


@dataclass(init=False)
class _BaseInitForgivingExtras():
    def __init__(self, **kwargs):
        names = set([f.name for f in fields(self)])
        for k, v in kwargs.items():
            if k in names:
                setattr(self, k, v)

@dataclass(init=False)
class AccountLimits(_BaseInitForgivingExtras):
    '''Account limits.'''
    subs: int
    data: int
    payload: int
    imports: int
    exports: int
    wildcards: bool
    conn: int
    leaf: int


@dataclass(init=False)
class Permissions(_BaseInitForgivingExtras):
    '''Default pub/sub permissions.'''
    allow: ty.List[str]
    deny: ty.List[str]

    def as_dict(self) -> ty.Dict[str, ty.List[str]]:
        return {
            'allow': self.allow,
            'deny': self.deny
        }


@dataclass
class UserLimits():
    '''User limits.'''
    subs: int
    data: int
    payload: int


class Auth():
    '''Base class for authentication objects'''
    _jwt_payload: ty.Dict[str, ty.Any]

    def __init__(self, jwt_token: str) -> None:
        """Initialize Auth object.

        Args:
            jwt_token (str): JWT token of the object.

        Raises:
            ValueError: Bad JWT token.
        """
        jwt_payload = _decode_jwt_payload(jwt_token)
        if not self._verify_payload(jwt_payload):
            raise ValueError("Invalid JWT type")
        self._jwt_payload = jwt_payload

    @classmethod
    def _verify_payload(cls, payload: ty.Dict[str, ty.Any]) -> bool:
        raise NotImplementedError

    @property
    def jwt_id(self) -> str:
        '''JWT ID.'''
        return self._jwt_payload['jti']

    @property
    def name(self) -> str:
        '''Name of an object'''
        return self._jwt_payload['name']

    @property
    def pub_key(self) -> str:
        '''Public nkey of object'''
        return self._jwt_payload['sub']

    @property
    def subject(self) -> str:
        '''JWT's subject. Pub key by convention.'''
        return self.pub_key

    @property
    def nats_props(self) -> ty.Dict[str, ty.Any]:
        '''NATS properties.'''
        return self._jwt_payload['nats']

    @property
    def issuer(self) -> str:
        '''Issuer nkey.'''
        return self._jwt_payload['iss']

    @property
    def issued_at(self) -> datetime:
        '''Issued at.'''
        return datetime.utcfromtimestamp(self._jwt_payload['iat'])


class Operator(Auth):
    '''Operator class.'''
    @classmethod
    def _verify_payload(cls, payload: ty.Dict[str, ty.Any]) -> bool:
        return payload['nats']['type'] == 'operator'


class Account(Auth):
    '''Account class.'''
    priv_key: ty.Optional[str] = None

    def __init__(self, jwt_token: str, priv_key: ty.Optional[str] = None) -> None:
        """Create Account object.

        Args:
            jwt_token (str): Account's JWT token.
            priv_key (ty.Optional[str], optional): Account's private key (seed). Defaults to None.
        """
        super().__init__(jwt_token)
        self.priv_key = priv_key

    @classmethod
    def _verify_payload(cls, payload: ty.Dict[str, ty.Any]) -> bool:
        return payload['nats']['type'] == 'account'

    @property
    def limits(self) -> AccountLimits:
        '''Default limits of an account.'''
        return AccountLimits(**self._jwt_payload['nats']['limits'])

    @property
    def sub_permissions(self) -> Permissions:
        '''Default sub permissions of an account.'''
        ps_dct = self._jwt_payload['nats']['default_permissions']['sub']
        return Permissions(allow=ps_dct['allow'] if 'allow' in ps_dct else [],
                           deny=ps_dct['deny'] if 'deny' in ps_dct else [])

    @property
    def pub_permissions(self) -> Permissions:
        '''Default pub permissions of an account.'''
        ps_dct = self._jwt_payload['nats']['default_permissions']['pub']
        return Permissions(allow=ps_dct['allow'] if 'allow' in ps_dct else [],
                           deny=ps_dct['deny'] if 'deny' in ps_dct else [])

    @property
    def has_key(self) -> bool:
        '''Check if account has a private key.'''
        return self.priv_key is not None


class User(Auth):
    '''User class.'''

    def __init__(self, jwt_token: str) -> None:
        self._full_jwt = jwt_token
        super().__init__(jwt_token)

    @property
    def jwt_token(self) -> str:
        '''JWT token of an user.'''
        return self._full_jwt

    @classmethod
    def _verify_payload(cls, payload: ty.Dict[str, ty.Any]) -> bool:
        return payload['nats']['type'] == 'user'

    @property
    def limits(self) -> UserLimits:
        '''Limits of an user.'''
        nats_dict = self._jwt_payload['nats']
        return UserLimits(subs=nats_dict['sub'], data=nats_dict['data'], payload=nats_dict['payload'])

    @property
    def sub_permissions(self) -> Permissions:
        '''Sub permissions of an user.'''
        return Permissions(**self._jwt_payload['nats']['sub'])

    @property
    def pub_permissions(self) -> Permissions:
        '''Pub permissions of an user.'''
        return Permissions(**self._jwt_payload['nats']['pub'])

    @property
    def src_networks(self) -> ty.Optional[ty.List[str]]:
        '''Allowed source networks of an user.'''
        return self._jwt_payload['nats']['src'] if 'src' in self._jwt_payload['nats'] else None

    @property
    def bearer(self) -> bool:
        '''Whether user can use bearer authentication.'''
        return self._jwt_payload['nats']['bearer_token'] if 'bearer_token' in self._jwt_payload['bearer_token'] else False

    @property
    def resp_ttl(self) -> timedelta:
        '''Response TTL of an user.'''
        seconds = self._jwt_payload['nats']['resp']['ttl'] / TTL_SCALE if 'resp' in self._jwt_payload['nats'] else 1.0
        return timedelta(seconds=seconds)

    @property
    def max_resp(self) -> int:
        '''Max response Count of an user.'''
        return self._jwt_payload['nats']['resp']['max'] if 'resp' in self._jwt_payload['nats'] else 1


class Credential():
    '''Credential class.'''

    def __init__(self, payload: str) -> None:
        '''Create Credential object.'''
        self._payload = payload

    @property
    def payload(self) -> str:
        '''Payload of object.'''
        return self._payload

    @property
    def jwt(self) -> dict:
        '''JWT section of credential'''
        payload_splitted = self._payload.split('\n')
        jwt_line_start = payload_splitted.index('-----BEGIN NATS USER JWT-----')
        jwt_line_end = payload_splitted.index('------END NATS USER JWT------')
        return _decode_jwt_payload('\n'.join(payload_splitted[jwt_line_start+1:jwt_line_end]))

    @property
    def nkey(self) -> str:
        '''Nkey section of credential'''
        payload_splitted = self._payload.split('\n')
        nkey_line_start = payload_splitted.index('-----BEGIN USER NKEY SEED-----')
        nkey_line_end = payload_splitted.index('------END USER NKEY SEED------')
        return '\n'.join(payload_splitted[nkey_line_start+1:nkey_line_end])


class KeyType(Enum):
    '''Key type enum.'''
    USER = 'user'
    ACCOUNT = 'account'
    OPERATOR = 'operator'
