import ldap
from csh_ldap.member import CSHMember
from csh_ldap.group import CSHGroup


class CSHLDAP:
    __ldap_uri__ = "ldaps://ldap.csh.rit.edu"

    def __init__(self, bind_dn, bind_pw, batch_mods=False):
        """Handler for bindings to CSH LDAP.

        Keyword arguments:
        batch_mods -- whether or not to batch LDAP writes (default False)
        """
        self.__con__ = ldap.initialize(self.__ldap_uri__)
        self.__con__.simple_bind_s(bind_dn, bind_pw)
        self.__mod_queue__ = {}
        self.__pending_mod_dn__ = []
        self.__batch_mods__ = batch_mods

    def get_member(self, val, uid=False):
        """Get a CSHMember object.

        Arguments:
        val -- the uuid (or uid) of the member

        Keyword arguments:
        uid -- whether or not val is a uid (default False)
        """
        return CSHMember(self, val, uid)

    def get_member_ibutton(self, val):
        """Get a CSHMember object.

        Arguments:
        val -- the iButton ID of the member

        Returns:
        None if the iButton supplied does not correspond to a CSH Member
        """
        members = self.__con__.search_s(
            CSHMember.__ldap_user_ou__,
            ldap.SCOPE_SUBTREE,
            "(ibutton=%s)" % val,
            ['entryUUID'])
        if len(members) > 0:
            return CSHMember(
                    self,
                    members[0][1]['entryUUID'][0].decode('utf-8'),
                    False)
        return None

    def get_group(self, val):
        """Get a CSHGroup object.

        Arguments:
        val -- the cn of the group

        """
        return CSHGroup(self, val)

    def get_con(self):
        """Get the PyLDAP Connection"""
        return self.__con__

    def enqueue_mod(self, dn, mod):
        """Enqueue a LDAP modification.

        Arguments:
        dn -- the distinguished name of the object to modify
        mod -- an ldap modfication entry to enqueue
        """
        # mark for update
        if dn not in self.__pending_mod_dn__:
            self.__pending_mod_dn__.append(dn)
            self.__mod_queue__[dn] = []

        self.__mod_queue__[dn].append(mod)

    def flush_mod(self):
        """Flush all pending LDAP modifications."""
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
