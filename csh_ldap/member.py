import ldap

class CSHMember:
    __con__ = None
    __search_val__ = None
    __ldap_user_ou__ = "ou=Users,dc=csh,dc=rit,dc=edu"
    __dn__ = None

    def __init__(self, con, search_val):
        self.__con__ = con
        self.__search_val__ = search_val

        self.__dn__ = con.search_s(
                self.__ldap_user_ou__,
                ldap.SCOPE_SUBTREE,
                "(entryUUID=%s)" % search_val,
                ['uid'])[0][0]

    def __getattr__(self, key):
        return self.__con__.search_s(
                self.__ldap_user_ou__,
                ldap.SCOPE_SUBTREE,
                "(entryUUID=%s)" % self.__search_val__,
                [key])

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
            ldap_mod = ldap.MOD_REPLACE
        else:
            ldap_mod = ldap.MOD_ADD

        mod_attrs = [(ldap_mod, key, value)]

        __con__.modify_s(__dn__, mod_attrs)
