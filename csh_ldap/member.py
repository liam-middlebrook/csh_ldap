import ldap

class CSHMember:
    __con__ = None
    __search_val__ = None

    def __init__(self, con, search_val):
        self.__con__ = con
        self.__search_val__ = search_val

        print(self.__con__.search_s('ou=Users,dc=csh,dc=rit,dc=edu',
            ldap.SCOPE_SUBTREE,
            "(entryUUID=%s)" % s,
            ['cn']))
