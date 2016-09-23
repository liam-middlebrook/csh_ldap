import ldap

class CSHLDAP:
    __con__ = None

    __ldap_uri__ = "ldaps://ldap.csh.rit.edu"
    __ldap_user_dn__ = "ou=Users,dc=csh,dc=rit,dc=edu"
    __ldap_app_dn__ = "ou=Apps,dc=csh,dc=rit,dc=edu"

    def __init__(self, bind_dn, bind_pw):
        self.__con__ = ldap.initialize(self.__ldap_uri__)
        self.__con__.simple_bind_s(bind_dn, bind_pw)
        pass

    def get_member(type, val):
        return CSHMember(self.__con__, val)
