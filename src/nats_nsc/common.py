import typing as ty
from dataclasses import dataclass


@dataclass
class Operator():
    name: str
    jwt_path: str
    pub_key: str
    jwt_payload: ty.Dict[str, ty.Any]


@dataclass
class Account():
    name: str
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
    def jwt(self) -> str:
        payload_splitted = self._payload.split('\n')
        jwt_line_start = payload_splitted.index('-----BEGIN NATS USER JWT-----')
        jwt_line_end = payload_splitted.index('------END NATS USER JWT------')
        return '\n'.join(payload_splitted[jwt_line_start+1:jwt_line_end])

    @property
    def nkey(self) -> str:
        payload_splitted = self._payload.split('\n')
        nkey_line_start = payload_splitted.index('-----BEGIN USER NKEY SEED-----')
        nkey_line_end = payload_splitted.index('------END USER NKEY SEED------')
        return '\n'.join(payload_splitted[nkey_line_start+1:nkey_line_end])
