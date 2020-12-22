from functools import wraps
import ldap
import srvlookup

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
        ldap_obj = method_args[0] if "CSHLDAP" in [t.__name__ for t in type(
                method_args[0]).__mro__] else method_args[0].__lib__
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
