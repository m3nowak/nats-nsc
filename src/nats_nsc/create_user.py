import typing as ty
from datetime import timedelta, datetime
import uuid
import base64
import json

import nkeys

from nats_nsc import common

HEADER = {
  "typ": "JWT",
  "alg": "ed25519-nkey"
}

def create_user(user_name: str, account: common.Account,
                pub_key: str,
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
                start: ty.Union[timedelta, datetime, None] = None,
                tag: ty.Optional[ty.List[str]] = None) -> common.User:
    '''Create user.'''
    if not account.has_key:
        raise ValueError('Account has no key')
    
    issued_at = start if isinstance(start, datetime) else datetime.utcnow()
    if isinstance(start, timedelta):
        issued_at += start

    
    pub = account.pub_permissions.as_dict()
    if allow_pub is None or allow_pubsub is None:
        pub['allow'] = []
        if allow_pub is not None:
            pub['allow'] += allow_pub
        if allow_pubsub is not None:
            pub['allow'] += allow_pubsub
    if deny_pub is not None or deny_pubsub is not None:
        pub['deny'] = []
        if deny_pub is not None:
            pub['deny'] += deny_pub
        if deny_pubsub is not None:
            pub['deny'] += deny_pubsub
    

    sub = account.sub_permissions.as_dict()
    if allow_sub is not None or allow_pubsub is not None:
        sub['allow'] = []
        if allow_sub is not None:
            sub['allow'] += allow_sub
        if allow_pubsub is not None:
            sub['allow'] += allow_pubsub
    if deny_sub is not None or deny_pubsub is not None:
        sub['deny'] = []
        if deny_sub is not None:
            sub['deny'] += deny_sub
        if deny_pubsub is not None:
            sub['deny'] += deny_pubsub
    
    resp = None
    if allow_pub_response is not None or response_ttl is not None:
        if allow_pub_response is None:
            allow_pub_response = 0 # Yea, I don't know why either, but that's how nsc works
        if response_ttl is None:
            response_ttl = timedelta(seconds=0)
        resp = {
            'max': allow_pub_response,
            'ttl': response_ttl.total_seconds() * common.TTL_SCALE
        }
    
    payload = {
        'jti': uuid.uuid4().hex,
        'iat': int(issued_at.timestamp()),
        'iss': account.pub_key,
        'name': user_name,
        'sub': pub_key,
        'nats': {
            'sub': sub,
            'pub': pub,
            "subs": account.limits.subs,
            "data": account.limits.data,
            "payload": account.limits.payload,
            "type": "user",
            "version": 2
        }
    }

    if expiry is not None:
        payload['exp'] = int((issued_at + expiry).timestamp())
    if resp is not None:
        payload['nats']['resp'] = resp
    if source_networks:
        payload['nats']['src'] = source_networks
    if bearer:
        payload['nats']['bearer_token'] = True
    if tag:
        payload['nats']['tags'] = tag

    to_sign = base64.urlsafe_b64encode(json.dumps(HEADER).encode()).strip(b'=') + b'.' +\
        base64.urlsafe_b64encode(json.dumps(payload).encode()).strip(b'=')
    
    user = nkeys.from_seed(account.priv_key.encode()) # type: ignore
    sig = user.sign(to_sign)
    user.wipe()
    jwt = to_sign + b'.' + base64.urlsafe_b64encode(sig).strip(b'=')
    return common.User(jwt_token=jwt.decode())

