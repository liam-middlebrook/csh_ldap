import ldap
from csh_ldap.member import CSHMember

class CSHLDAP:
    __con__ = None

    __ldap_uri__ = "ldaps://ldap.csh.rit.edu"

    def __init__(self, bind_dn, bind_pw):
        self.__con__ = ldap.initialize(self.__ldap_uri__)
        self.__con__.simple_bind_s(bind_dn, bind_pw)
        pass

    def get_member(self, val):
        return CSHMember(self.__con__, val)
