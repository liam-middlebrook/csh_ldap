import ldap


class CSHMember:
    __ldap_user_ou__ = "ou=Users,dc=csh,dc=rit,dc=edu"

    def __init__(self, lib, search_val, uid):
        self.__dict__['__lib__'] = lib
        self.__dict__['__con__'] = lib.get_con()

        if uid:
            self.__dict__['__dn__'] = self.__con__.search_s(
                    self.__ldap_user_ou__,
                    ldap.SCOPE_SUBTREE,
                    "(uid=%s)" % search_val,
                    ['entryUUID'])[0][0]
        else:
            self.__dict__['__dn__'] = self.__con__.search_s(
                    self.__ldap_user_ou__,
                    ldap.SCOPE_SUBTREE,
                    "(entryUUID=%s)" % search_val,
                    ['uid'])[0][0]

    def get(self, key):
        return self.__getattr__(key, as_list=True)

    def groups(self):
        return self.get('memberOf')

    def in_group(self, group):
        if 'cn' not in group:
            group = "cn=" + group + ",ou=Groups,dc=csh,dc=rit,dc=edu"
        return group in self.groups()

    def __getattr__(self, key, as_list=False):
        res = self.__con__.search_s(
                self.__dn__,
                ldap.SCOPE_BASE,
                "(objectClass=*)",
                [key])

        if as_list:
            return [v.decode('utf-8') for v in res[0][1][key]]
        else:
            return res[0][1][key][0].decode('utf-8')

    def __setattr__(self, key, value):
        ldap_mod = None

        exists = self.__con__.search_s(
                self.__dn__,
                ldap.SCOPE_BASE,
                "(objectClass=*)",
                [key])

        if value is None or value == "":
            ldap_mod = ldap.MOD_DELETE
        elif exists[0][1] == {}:
            ldap_mod = ldap.MOD_ADD
        else:
            ldap_mod = ldap.MOD_REPLACE

        if value is None:
            mod = (ldap_mod, key, None)
        else:
            mod = (ldap_mod, key, value.encode('ascii'))

        if self.__lib__.__batch_mods__:
            self.__lib__.enqueue_mod(self.__dn__, mod)
        else:
            mod_attrs = [mod]
            self.__con__.modify_s(self.__dn__, mod_attrs)
