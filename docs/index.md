# nats-nsc documentation

Python utility for user JWT token generation
## Basic usage example

```python
from datetime import timedelta

from nats_nsc import Account, Operator
from nats_nsc.create_user import create_user
acc = Account(open('path_to_account_jwt.jwt').read(),
              open('path_to_account_nkey_seed.nk').read()
             )

usr_nkey = input() # user nkey should be supplied by requesting party
usr = create_user('user0', 
                  acc,
                  usr_nkey,
                  allow_pub=['foo', 'bar.*'],
                  allow_sub=['_INBOX.user0.>', 'bar.*'],
                  expiry=timedelta(hours=1)
                  )
print(f"User's jwt token: {usr.jwt_token}")
```
