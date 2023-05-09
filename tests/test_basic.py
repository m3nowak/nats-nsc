import jwt
from nats_nsc import Account, Operator, create_user

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
    a = usr.full_jwt
    pass
