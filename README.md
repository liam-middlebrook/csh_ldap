# csh_ldap

[![PyPI version](https://badge.fury.io/py/csh_ldap.svg)](https://badge.fury.io/py/csh_ldap)
[![Build Status](https://travis-ci.org/liam-middlebrook/csh_ldap.svg?branch=master)](https://travis-ci.org/liam-middlebrook/csh_ldap)

Python 3 ORM for CSH LDAP


## Installation

`pip install csh_ldap`


## Usage

```
import csh_ldap

# Create an unbatched instance
instance = csh_ldap.CSHLDAP(bind_dn, bind_pw)

# Create an batched instance
instance_batched = csh_ldap.CSHLDAP(bind_dn, bind_pw, batch_mods=True)

# Get member by UUID
liam = instance.get_member(uuid_of_liam)

# Get member by UID
liam = instance.get_member(uid_of_liam, uid=True)

# Get cn of member
print(liam.cn)

# Set cn of member
liam.cn = "Liam Middlebrook"

# Setting attributes to None removes them
liam.roomNumber = None

# Process batched writes per-dn
instance_batched.flush_mod()
```
