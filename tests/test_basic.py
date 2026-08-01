from typing import cast

import jwt
import nkeys

from nats_nsc import Account, Operator
from nats_nsc.create_user import create_user


def _test_account() -> Account:
    seed = nkeys.encode_seed(bytes(range(32)), nkeys.PREFIX_BYTE_ACCOUNT)
    key_pair = nkeys.from_seed(seed)
    token = jwt.encode(
        {
            "jti": "test-account",
            "iat": 0,
            "iss": "test-operator",
            "name": "nats-nsc-testing",
            "sub": cast(bytes, key_pair.public_key).decode(),
            "nats": {
                "limits": {
                    "subs": -1,
                    "data": -1,
                    "payload": -1,
                    "imports": -1,
                    "exports": -1,
                    "wildcards": True,
                    "conn": -1,
                    "leaf": -1,
                },
                "default_permissions": {"pub": {}, "sub": {}},
                "type": "account",
                "version": 2,
            },
        },
        key="",
        algorithm="none",
    )
    return Account(token, seed.decode())


def test_basic_workflow():
    opr = Operator(open("tests/nsc_workdir/nats-nsc-testing/nats-nsc-testing.jwt").read())
    assert opr.name == "nats-nsc-testing"
    acc = _test_account()
    assert acc.name == "nats-nsc-testing"
    usr = create_user(
        "user0",
        acc,
        "UDZBHCCXJREZRPMRHZFEBNF6TTOVYUMB4J36GM6UJUQUJMRC5GBZ5BLG",
        allow_pub=["foo", "bar.*"],
        allow_sub=["_INBOX.user0.>", "bar.*"],
    )
    assert usr.name == "user0"
    assert set(usr.pub_permissions.allow) == set(["foo", "bar.*"])
    assert set(usr.sub_permissions.allow) == set(["_INBOX.user0.>", "bar.*"])
    assert usr.subject == "UDZBHCCXJREZRPMRHZFEBNF6TTOVYUMB4J36GM6UJUQUJMRC5GBZ5BLG"


def test_docs_example():
    from datetime import timedelta

    from nats_nsc.create_user import create_user

    acc = _test_account()

    # usr_nkey = input() # user nkey should be supplied by requesting party
    usr_nkey = "UDZBHCCXJREZRPMRHZFEBNF6TTOVYUMB4J36GM6UJUQUJMRC5GBZ5BLG"
    usr = create_user(
        "user0",
        acc,
        usr_nkey,
        allow_pub=["foo", "bar.*"],
        allow_sub=["_INBOX.user0.>", "bar.*"],
        expiry=timedelta(hours=1),
    )
    assert usr.name == "user0"
    assert set(usr.pub_permissions.allow) == set(["foo", "bar.*"])
    assert set(usr.sub_permissions.allow) == set(["_INBOX.user0.>", "bar.*"])
    assert usr.subject == "UDZBHCCXJREZRPMRHZFEBNF6TTOVYUMB4J36GM6UJUQUJMRC5GBZ5BLG"
    assert len(usr.jwt_token.split(".")) == 3
    # print(f"User's jwt token: {usr.jwt_token}")
