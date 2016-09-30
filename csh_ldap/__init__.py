import ldap
from csh_ldap.member import CSHMember
from csh_ldap.group import CSHGroup


class CSHLDAP:
    __ldap_uri__ = "ldaps://ldap.csh.rit.edu"

    def __init__(self, bind_dn, bind_pw, batch_mods=False):
        self.__con__ = ldap.initialize(self.__ldap_uri__)
        self.__con__.simple_bind_s(bind_dn, bind_pw)
        self.__mod_queue__ = {}
        self.__pending_mod_dn__ = []
        self.__batch_mods__ = batch_mods
        pass

    def get_member(self, val, uid=False):
        return CSHMember(self, val, uid)

    def get_group(self, val):
        return CSHGroup(self, val)

    def get_con(self):
        return self.__con__

    def enqueue_mod(self, dn, mod):
        # mark for update
        if dn not in self.__pending_mod_dn__:
            self.__pending_mod_dn__.append(dn)
            self.__mod_queue__[dn] = []

        self.__mod_queue__[dn].append(mod)

    def flush_mod(self):
        for dn in self.__pending_mod_dn__:
            try:
                self.__con__.modify_s(dn, self.__mod_queue__[dn])
            except ldap.TYPE_OR_VALUE_EXISTS:
                print("Error! Conflicting Batch Modification: %s"
                      % str(self.__mod_queue__[dn]))
                continue
            except ldap.NO_SUCH_ATTRIBUTE:
                print("Error! Conflicting Batch Modification: %s"
                      % str(self.__mod_queue__[dn]))
                continue
            self.__mod_queue__[dn] = None
        self.__pending_mod_dn__ = []
