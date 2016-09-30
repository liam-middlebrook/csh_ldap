import ldap


class CSHGroup:
    __ldap_group_ou__ = "ou=Groups,dc=csh,dc=rit,dc=edu"

    def __init__(self, lib, search_val):
        """Object Model for CSH LDAP groups.

        Arguments:
        lib -- handle to a CSHLDAP instance
        search_val -- the cn of the LDAP group to bind to
        """
        self.__dict__['__lib__'] = lib
        self.__dict__['__con__'] = lib.get_con()

        self.__dict__['__dn__'] = self.__con__.search_s(
                self.__ldap_group_ou__,
                ldap.SCOPE_SUBTREE,
                "(cn=%s)" % search_val,
                ['cn'])[0][0]

    def get_members(self):
        """Return all members in the group"""
        res = self.__con__.search_s(
                self.__dn__,
                ldap.SCOPE_BASE,
                "(objectClass=*)",
                ['member'])

        ret = []
        for val in res[0][1]['member']:
            try:
                ret.append(val.decode('utf-8'))
            except UnicodeDecodeError:
                ret.append(val)
            except KeyError:
                continue

        return ret

    def check_member(self, dn):
        """Check if a Member is in the bound group.

        Arguments:
        dn -- the distinguished name of the member's LDAP object
        """
        res = self.__con__.search_s(
                self.__dn__,
                ldap.SCOPE_BASE,
                "(member=%s)" % dn,
                ['entryUUID'])
        return len(res) > 0

    def add_member(self, dn):
        """Add a member to the bound group

        Arguments:
        dn -- the distinguished name of the member's LDAP object
        """
        ldap_mod = None

        if self.check_member(dn):
            return

        mod = (ldap.MOD_ADD, 'member', dn.encode('ascii'))

        if self.__lib__.__batch_mods__:
            self.__lib__.enqueue_mod(self.__dn__, mod)
        else:
            mod_attrs = [mod]
            self.__con__.modify_s(self.__dn__, mod_attrs)

    def del_member(self, dn):
        """Remove a member from the bound group

        Arguments:
        dn -- the distinguished name of the member's LDAP object
        """
        ldap_mod = None

        if not self.check_member(dn):
            return

        mod = (ldap.MOD_DELETE, 'member', dn.encode('ascii'))

        if self.__lib__.__batch_mods__:
            self.__lib__.enqueue_mod(self.__dn__, mod)
        else:
            mod_attrs = [mod]
            self.__con__.modify_s(self.__dn__, mod_attrs)
