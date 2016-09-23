import ldap

class CSHMember:
    __con__ = None
    __search_val__ = None
    __ldap_user_ou__ = "ou=Users,dc=csh,dc=rit,dc=edu"

    def __init__(self, con, search_val):
        self.__con__ = con
        self.__search_val__ = search_val

    def __getattr__(self, key):
        return self.__con__.search_s(
                self.__ldap_user_ou__,
                ldap.SCOPE_SUBTREE,
                "(entryUUID=%s)" % self.__search_val__,
                [key])
