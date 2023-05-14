from nats_nsc import Account, Operator
from nats_nsc.create_user import create_user

def test_basic_workflow():
    opr = Operator(open('tests/nsc_workdir/nats-nsc-testing/nats-nsc-testing.jwt').read())
    assert opr.name == 'nats-nsc-testing'
    acc = Account(open('tests/nsc_workdir/nats-nsc-testing/accounts/nats-nsc-testing/nats-nsc-testing.jwt').read(),
                  open('tests/nsc_workdir/keys/A/DD/ADDMOZZDAAU5LB4UML6N2QLIVCGXLEIYZZ5TT4YJCUKQT2FQIE25BZAG.nk').read())
    assert acc.name == 'nats-nsc-testing'
    usr = create_user('user0', acc, 'UDZBHCCXJREZRPMRHZFEBNF6TTOVYUMB4J36GM6UJUQUJMRC5GBZ5BLG',
                      allow_pub=['foo', 'bar.*'], allow_sub=['_INBOX.user0.>', 'bar.*'])
    assert usr.name == 'user0'
    assert set(usr.pub_permissions.allow) == set(['foo', 'bar.*'])
    assert set(usr.sub_permissions.allow) == set(['_INBOX.user0.>', 'bar.*'])
    assert usr.subject == 'UDZBHCCXJREZRPMRHZFEBNF6TTOVYUMB4J36GM6UJUQUJMRC5GBZ5BLG'

def test_docs_example():
    from datetime import timedelta

    from nats_nsc import Account
    from nats_nsc.create_user import create_user
    _path_to_account_jwt = 'tests/nsc_workdir/nats-nsc-testing/accounts/nats-nsc-testing/nats-nsc-testing.jwt'
    _path_to_account_nkey_seed = 'tests/nsc_workdir/keys/A/DD/ADDMOZZDAAU5LB4UML6N2QLIVCGXLEIYZZ5TT4YJCUKQT2FQIE25BZAG.nk'
    acc = Account(open(_path_to_account_jwt).read(),
                open(_path_to_account_nkey_seed).read()
                )

    #usr_nkey = input() # user nkey should be supplied by requesting party
    usr_nkey = 'UDZBHCCXJREZRPMRHZFEBNF6TTOVYUMB4J36GM6UJUQUJMRC5GBZ5BLG'
    usr = create_user('user0', 
                    acc,
                    usr_nkey,
                    allow_pub=['foo', 'bar.*'],
                    allow_sub=['_INBOX.user0.>', 'bar.*'],
                    expiry=timedelta(hours=1)
                    )
    assert usr.name == 'user0'
    assert set(usr.pub_permissions.allow) == set(['foo', 'bar.*'])
    assert set(usr.sub_permissions.allow) == set(['_INBOX.user0.>', 'bar.*'])
    assert usr.subject == 'UDZBHCCXJREZRPMRHZFEBNF6TTOVYUMB4J36GM6UJUQUJMRC5GBZ5BLG'
    assert len(usr.jwt_token.split('.')) == 3
    #print(f"User's jwt token: {usr.jwt_token}")

