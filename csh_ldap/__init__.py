import ldap
from csh_ldap.member import CSHMember

class CSHLDAP:
    __ldap_uri__ = "ldaps://ldap.csh.rit.edu"

    def __init__(self, bind_dn, bind_pw, batch_mods=False):
        self.__con__ = ldap.initialize(self.__ldap_uri__)
        self.__con__.simple_bind_s(bind_dn, bind_pw)
        self.__mod_queue__ = {}
        self.__pending_mod_dn__ = []
        self.__batch_mods__ = batch_mods
        pass

    def get_member(self, val):
        return CSHMember(self, val)

    # TODO add queue for CSH modlists

    # dict of dn's to pending modlists
    # clear by flush

    def get_con(self):
        return self.__con__

    def enqueue_mod(self, dn, mod):
        # mark for update
        if not dn in self.__pending_mod_dn__:
            self.__pending_mod_dn__.append(dn)
            self.__mod_queue__[dn] = None

        self.__mod_queue__[dn].append(mod)

    def flush_mod(self):
        for dn in self.__pending_mod_dn__:
            self.__con__.modify_s(dn, self.__mod_queue__[dn])
            self.__mod_queue__[dn] = None
        self.__pending_mod_dn__ = []
