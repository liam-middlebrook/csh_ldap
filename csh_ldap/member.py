import ldap


class CSHMember:
    __ldap_user_ou__ = "cn=users,cn=accounts,dc=csh,dc=rit,dc=edu"
    __ldap_base_dn__ = "dc=csh,dc=rit,dc=edu"

    def __init__(self, lib, search_val, uid):
        """Object Model for CSH LDAP users.

        Arguments:
        lib -- handle to a CSHLDAP instance
        search_val -- the uuid (or uid) of the member to bind to
        uid -- whether or not search_val is a uid
        """
        self.__dict__['__lib__'] = lib
        self.__dict__['__con__'] = lib.get_con()

        res = None

        if uid:
            res = self.__con__.search_s(
                    self.__ldap_base_dn__,
                    ldap.SCOPE_SUBTREE,
                    "(uid=%s)" % search_val,
                    ['ipaUniqueID'])
        else:
            res = self.__con__.search_s(
                    self.__ldap_base_dn__,
                    ldap.SCOPE_SUBTREE,
                    "(ipaUniqueID=%s)" % search_val,
                    ['uid'])

        if res > 0:
            self.__dict__['__dn__'] = res[0][0]
        else:
            raise KeyError("Invalid Search Name")

    def get(self, key):
        """Get an attribute from the bound CSH LDAP member object.

        Arguments:
        key -- the attribute to get the value of
        """
        return self.__getattr__(key, as_list=True)

    def groups(self):
        """Get the list of Groups (by dn) that the bound CSH LDAP member object
        is in.
        """
        return self.get('memberof') + self.get('memberofindirect')

    def in_group(self, group, dn=False):
        """Get whether or not the bound CSH LDAP member object is part of a
        group.

        Arguments:
        group -- the CSHGroup object (or distinguished name) of the group to
                 check membership for
        """
        if dn:
            return group in self.groups()
        return group.check_member(self)

    def get_dn(self):
        """Get the distinguished name of the bound LDAP object"""
        return self.__dn__

    def __getattr__(self, key, as_list=False):
        res = self.__con__.search_s(
                self.__dn__,
                ldap.SCOPE_BASE,
                "(objectClass=*)",
                [key])

        if as_list:
            ret = []
            for val in res[0][1][key]:
                try:
                    ret.append(val.decode('utf-8'))
                except UnicodeDecodeError:
                    ret.append(val)
                except KeyError:
                    continue

            return ret
        else:
            try:
                return res[0][1][key][0].decode('utf-8')
            except UnicodeDecodeError:
                return res[0][1][key][0]
            except KeyError:
                return None

    def __setattr__(self, key, value):
        ldap_mod = None

        exists = self.__con__.search_s(
                self.__dn__,
                ldap.SCOPE_BASE,
                "(objectClass=*)",
                [key])

        if value is None or value == "":
            ldap_mod = ldap.MOD_DELETE
            if exists[0][1] == {}:
                # if element doesn't exist STOP
                return
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
        elif not self.__lib__.__ro__:
            mod_attrs = [mod]
            self.__con__.modify_s(self.__dn__, mod_attrs)
        else:
            if ldap_mod == ldap.MOD_DELETE:
                mod_str = "DELETE"
            elif ldap_mod == ldap.MOD_ADD:
                mod_str = "ADD"
            else:
                mod_str = "REPLACE"
            print("{} FIELD {} WITH {} FOR {}".format(mod_str,
                                                      key,
                                                      value,
                                                      self.__dn__))
