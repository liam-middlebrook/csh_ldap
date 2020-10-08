from functools import wraps
from enum import Enum
import ldap
from ldap.ldapobject import ReconnectLDAPObject
import srvlookup
from csh_ldap.member import CSHMember
from csh_ldap.group import CSHGroup

MAX_RECONNECTS = 3


def reconnect_on_fail(method):
    """
    Decorator for CSHLDAP operations that attempts to reconnect and recall a
    method on a failed call.

    :param method: Method to call
    :return: wrapper function
    """

    @wraps(method)
    def wrapper(*method_args, **method_kwargs):
        """
        Wrapper for method, calls method and returns the result if successful,
         otherwise tries reconnecting.

        :param method_args: method's arguments
        :param method_kwargs: method's keyword arguments
        :return: result of method call
        """
        max_reconnects = MAX_RECONNECTS
        ldap_obj = method_args[0] if isinstance(method_args[0], CSHLDAP) else\
            method_args[0].__lib__
        while max_reconnects:
            try:
                result = method(*method_args, **method_kwargs)
                return result
            except (ldap.SERVER_DOWN, ldap.TIMEOUT):
                ldap_srvs = srvlookup.lookup(
                    "ldap", "tcp", ldap_obj.__domain__)
                ldap_obj.ldap_uris = ['ldaps://' + uri.hostname
                                      for uri in ldap_srvs]

                for uri in ldap_obj.ldap_uris:
                    try:
                        ldap_obj.__con__.reconnect(uri)
                        ldap_obj.server_uri = uri
                        result = method(*method_args, **method_kwargs)
                        return result
                    except (ldap.SERVER_DOWN, ldap.TIMEOUT):
                        continue
                max_reconnects -= 1
                if max_reconnects == 0:
                    raise

    return wrapper


class CSHLDAP:
    __domain__ = "csh.rit.edu"

    @reconnect_on_fail
    def __init__(self, bind_dn, bind_pw, batch_mods=False,
                 sasl=False, ro=False):
        """Handler for bindings to CSH LDAP.

        Keyword arguments:
        batch_mods -- whether or not to batch LDAP writes (default False)
        sasl -- whether or not to bypass bind_dn and bind_pw and use SASL bind
        ro -- whether or not CSH LDAP is in read only mode (default False)
        """
        if ro:
            print("########################################\n"
                  "#                                      #\n"
                  "#    CSH LDAP IS IN READ ONLY MODE     #\n"
                  "#                                      #\n"
                  "########################################")
        ldap_srvs = srvlookup.lookup("ldap", "tcp", self.__domain__)
        self.ldap_uris = ['ldaps://' + uri.hostname for uri in ldap_srvs]
        self.server_uri = None
        self.__con__ = None
        for uri in self.ldap_uris:
            try:
                self.__con__ = ReconnectLDAPObject(uri)
                self.server_uri = uri
            except (ldap.SERVER_DOWN, ldap.TIMEOUT):
                continue

        if self.__con__ is None:
            raise ldap.SERVER_DOWN

        if sasl:
            self.__con__.sasl_non_interactive_bind_s('')
        else:
            self.__con__.simple_bind_s(bind_dn, bind_pw)
        self.__mod_queue__ = {}
        self.__pending_mod_dn__ = []
        self.__batch_mods__ = batch_mods
        self.__ro__ = ro

    @reconnect_on_fail
    def get_member(self, val, uid=False):
        """Get a CSHMember object.

        Arguments:
        val -- the uuid (or uid) of the member

        Keyword arguments:
        uid -- whether or not val is a uid (default False)
        """
        return CSHMember(self, val, uid)

    @reconnect_on_fail
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

    @reconnect_on_fail
    def get_member_slackuid(self, slack):
        """Get a CSHMember object.

        Arguments:
        slack -- the Slack UID of the member

        Returns:
        None if the Slack UID provided does not correspond to a CSH Member
        """
        members = self.__con__.search_s(
            CSHMember.__ldap_user_ou__,
            ldap.SCOPE_SUBTREE,
            "(slackuid=%s)" % slack,
            ['ipaUniqueID'])
        if members:
            return CSHMember(
                self,
                members[0][1]['ipaUniqueID'][0].decode('utf-8'),
                False)
        return None

    @reconnect_on_fail
    def get_group(self, val):
        """Get a CSHGroup object.

        Arguments:
        val -- the cn of the group

        """
        return CSHGroup(self, val)

    def get_con(self):
        """Get the PyLDAP Connection"""
        return self.__con__

    @reconnect_on_fail
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

    @reconnect_on_fail
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
