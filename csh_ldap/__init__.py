import ldap
from ldap.ldapobject import ReconnectLDAPObject
from csh_ldap.member import CSHMember
from csh_ldap.group import CSHGroup


class CSHLDAP:
    __ldap_uri__ = "ldaps://csh-ds01.csh.rit.edu"

    def __init__(self, bind_dn, bind_pw, batch_mods=False,
                 sasl=False, ro=False):
        """Handler for bindings to CSH LDAP.

        Keyword arguments:
        batch_mods -- whether or not to batch LDAP writes (default False)
        sasl -- whether or not to bypass bind_dn and bind_pw and use SASL bind
        """
        if ro:
            print("########################################\n"
                  "#                                      #\n"
                  "#    CSH LDAP IS IN READ ONLY MODE     #\n"
                  "#                                      #\n"
                  "########################################")
        self.__con__ = ReconnectLDAPObject(self.__ldap_uri__)
        if sasl:
            self.__con__.sasl_non_interactive_bind_s('')
        else:
            self.__con__.simple_bind_s(bind_dn, bind_pw)
        self.__mod_queue__ = {}
        self.__pending_mod_dn__ = []
        self.__batch_mods__ = batch_mods
        self.__ro__ = ro

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
            ['ipaUniqueID'])
        if members:
            return CSHMember(
                    self,
                    members[0][1]['ipaUniqueID'][0].decode('utf-8'),
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

    def get_directorship_heads(self, val):
        """Get the head of a directorship

        Arguments:
        val -- the cn of the directorship
        """

        __ldap_group_ou__ = "cn=groups,cn=accounts,dc=csh,dc=rit,dc=edu"

        res = self.__con__.search_s(
                __ldap_group_ou__,
                ldap.SCOPE_SUBTREE,
                "(cn=eboard-%s)" % val,
                ['member'])

        ret = []
        for member in res[0][1]['member']:
            try:
                ret.append(member.decode('utf-8'))
            except UnicodeDecodeError:
                ret.append(member)
            except KeyError:
                continue

        return [CSHMember(self,
                dn.split('=')[1].split(',')[0],
                True)
                for dn in ret]

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
                if self.__ro__:
                    for mod in self.__mod_queue__[dn]:
                        if mod[0] == ldap.MOD_DELETE:
                            mod_str = "DELETE"
                        elif mod[0] == ldap.MOD_ADD:
                            mod_str = "ADD"
                        else:
                            mod_str = "REPLACE"
                        print("{} VALUE {} = {} FOR {}".format(mod_str,
                                                               mod[1],
                                                               mod[2],
                                                               dn))
                else:
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
