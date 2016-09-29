import ldap

class CSHMember:
    __ldap_user_ou__ = "ou=Users,dc=csh,dc=rit,dc=edu"

    def __init__(self, con, search_val):
        self.__dict__['__con__'] = con
        self.__dict__['__search_val__'] = search_val

        self.__dict__['__dn__'] = con.search_s(
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
                self.__ldap_user_ou__,
                ldap.SCOPE_SUBTREE,
                "(entryUUID=%s)" % self.__search_val__,
                [key])

        if as_list:
            return [v.decode('utf-8') for v in res[0][1][key]]
        else:
            return res[0][1][key][0].decode('utf-8')


    def __setattr__(self, key, value):
        ldap_mod = None

        exists = self.__con__.search_s(
                self.__ldap_user_ou__,
                ldap.SCOPE_SUBTREE,
                "(entryUUID=%s)" % self.__search_val__,
                [key])

        if value is None or value == "":
            ldap_mod = ldap.MOD_DELETE
        elif exists[0][1] == {}:
            ldap_mod = ldap.MOD_ADD
        else:
            ldap_mod = ldap.MOD_REPLACE

        mod_attrs = [(ldap_mod, key, value)]

        self.__con__.modify_s(self.__dn__, mod_attrs)
