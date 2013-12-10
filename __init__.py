"""
LDAP utilities used primarily for querying an LDAP server and working with the
results.
"""
import binascii
import ctypes
import ldap
import logging
import struct

from django.conf import settings

from .models import LdapGroup

logger = logging.getLogger(__name__)


def convert_binary_sid_to_str(sid):
    """
    Converts the binary data structure of an Active Directory (AD) security
    identifier (SID) to a human-readable string.
    """
    # Start building the string.
    sid_str = ["S-"]

    # Convert the binary string to hex. Remember the hex string represents
    # each byte of data with 2 characters, so the string is twice as long as
    # the data. Hence the need to multiply by two, as seen below.
    hex_str = binascii.hexlify(sid)
    byte_c = 0 #byte count

    # hex_str[0:2], first byte - revision
    substr = hex_str[byte_c:byte_c + 2]
    hex_data = ctypes.create_string_buffer(substr.decode('hex'), 2)
    sid_str.append(str(struct.unpack('H', hex_data)[0])) # Two bytes
    sid_str.append("-")
    byte_c += 2

    # hex_str[2:4], second byte - number of dashes
    substr = hex_str[byte_c: byte_c + 2]
    hex_data = ctypes.create_string_buffer(substr.decode('hex'), 2)
    count = struct.unpack('H', hex_data)[0] # ditto, only two bytes
    byte_c += 2

    # hex_str[4:16], next six bytes - SECURITY_NT_AUTHORITY
    # This is freakin' ugly, a 6 byte string in big-endian format.
    # Which is, of course, different than the rest of the SID.
    substr = hex_str[byte_c:byte_c + (2*6)] # Two chars/byte, 6 bytes
    hex_data = ctypes.create_string_buffer(substr.decode('hex'), 6)
    sid_str.append(str(struct.unpack('>IH', hex_data)[1])) # Big endian
    byte_c += (2*6)

    # hex_str[16: the end of the string, based on the count]
    # Ok, now things are somewhat sane, get the rest of the SID.
    for i in range(0, count):
        sid_str.append('-')
        substr = hex_str[byte_c:byte_c + (2*4)] #two chars/byte, 4 bytes
        hex_data = ctypes.create_string_buffer(substr.decode('hex'), 4)
        sid_str.append(str(struct.unpack('<I', hex_data)[0])) # Little endian
        byte_c += (2*4)

    return "".join(sid_str)


class LDAPResult(object):
    """
    Represents a single LDAP result which is typically a dictionary of LDAP
    key/value pairs.

    This class allows values to be accessed as instance attributes named after
    the keys.
    """
    def __init__(self, dn, ldap, **kwargs):
        self.dn = dn
        self._ldap = ldap
        self.cn = kwargs.pop("cn", None)
        self.__dict__.update(**kwargs)

    def __unicode__(self):
        """
        Returns a display value for this result based on the common name.
        """
        if self.cn is not None:
            return "".join(self.cn)
        else:
            return self.dn

    def __repr__(self):
        return "<%s: %s>" % (self.__class__.__name__, self.__unicode__())

    @property
    def groups(self):
        """
        Returns all groups associated with this LDAP entity's distinguished
        name.
        """
        if not hasattr(self, "_groups"):
            self._groups = self._ldap.get_token_groups_by_dn(self.dn)
        return self._groups


class LDAP(object):
    """
    Provides access to query an LDAP server.
    """

    def __init__(self, conf_section, scope=None):
        """
        Prepares the LDAP object for connecting to an LDAP service as defined in
        a configuration section of the LDAP configuration file.

        The conf_section defines a server, dn, bind password, and base for the
        LDAP service.

        Example usage for an LDAP configuration file with a "wwu" section:
        >>> l = LDAP("wwu")
        """
        if not hasattr(settings, "LDAP_SOURCES"):
            raise Exception("Please define LDAP_SOURCES in your settings")

        if scope is None:
            self.scope = ldap.SCOPE_SUBTREE
        else:
            self.scope = scope

        if conf_section in settings.LDAP_SOURCES:
            config = settings.LDAP_SOURCES[conf_section]
            self.server = config.get("server")
            self.dn = config.get("dn")
            self.bindpw = config.get("bindpw")
            self.base = config.get("base")
        else:
            raise Exception("LDAP configuration not found for %s" % conf_section)

    def bind(self):
        """
        Initializes an LDAP instance and binds to the predefined server.
        """
        self.ldap = ldap.initialize(self.server)
        self.ldap.simple_bind(self.dn, self.bindpw)

    def unbind(self):
        """
        Unbinds the current LDAP instance.
        """
        self.ldap.unbind()

    def get_token_groups_by_dn(self, dn):
        """
        Get a list of token group distinguished names for the given
        distinguished name (DN).

        Token groups are binary ids for all groups a user belongs to in the AD
        tree.
        """
        logging.debug("Getting token groups for %s", dn)

        query = "(objectClass=*)"
        attributes = ["tokenGroups"]
        results = self.search(
            query,
            base=dn,
            scope=ldap.SCOPE_BASE,
            attributes=attributes
        )
        result = results[0]

        # Convert binary SIDs to strings. All references to SIDs from this point
        # on are references to the string representation of those SIDs.
        token_group_sids = [convert_binary_sid_to_str(sid)
                            for sid in getattr(result, attributes[0])]

        # Lookup previously defined security identifiers (SIDs).
        groups = LdapGroup.objects.filter(sid__in=token_group_sids)
        token_groups = [group.name for group in groups if group.name]
        logging.debug("Found %s groups in the database", groups.count())

        # Filter SIDs that haven't been defined.
        new_sids = set(token_group_sids) - set([group.sid for group in groups])
        logging.debug("Looking up %s new groups", len(new_sids))

        # Get the distinguished name (DN) for each token group SID filtering out
        # any SIDs that don't have a DN (i.e., group name is None).
        for sid in new_sids:
            token_group = self.get_token_group_name_by_sid(sid)
            logger.debug("Found new group: %s" % token_group)
            if token_group != "":
                token_groups.append(token_group)

        return token_groups

    def get_token_group_name_by_sid(self, sid):
        """
        Get the name for a token group based on its SID.

        SID/distinguished name pairs are cached because they change
        infrequently.
        """
        # SIDs are stored in LDAP as binary strings. Each SID needs to be
        # converted from binary to a string representation before querying
        # LDAP for the token group distinguished name.
        attributes = []
        query = "(objectSid=%s)" % sid
        results = self.search(query, attributes=attributes)
        if len(results) > 0:
            # Use the token group's common name (CN) if it has
            # one. Otherwise, fall back on the distinguished name (DN).
            if results[0].cn:
                name = " ".join(results[0].cn)
            else:
                name = results[0].dn

            # Lowercase group names because they are inconsistently cased.
            name = name.lower()
        else:
            name = ""

        # Store the SID/name pair even if the name is empty to avoid an LDAP
        # query.
        LdapGroup.objects.get_or_create(sid=sid, name=name)

        return name

    def search(self, query, base=None, scope=None, attributes=None):
        """
        Performs a synchronous search through all subtrees for the given query.

        Result rows are loaded into LDAPResult objects so results can be
        accessed easily through object attributes.
        """
        if base is None:
            base = self.base

        if scope is None:
            scope = self.scope

        if attributes is None:
            attributes = ["cn"]

        self.bind()
        results = self.ldap.search_s(base, scope, query, attributes)
        self.unbind()

        return [LDAPResult(dn, ldap=self, **row) for dn, row in results]

    def search_groups(self, query, attributes=None):
        """
        Searches for groups that match the given query. If ``attributes`` is
        specified, only the values in that list are returned in the LDAPResult.
        """
        query = "(&(objectClass=group)(cn=%s))" % query
        return self.search(query, attributes=attributes)

    def search_people(self, query, attributes=None):
        """
        Searches for users that match the given query. The query usually
        includes a user's first and last name.
        """
        query = "(&(objectClass=person)(cn=%s))" % query
        return self.search(query, attributes=attributes)

    def get_person_by_username(self, username):
        """
        Searches for users by the given unique username. Thus, if there are any
        results, there will only be one.
        """
        query = "(&(objectClass=person)(sAMAccountName=%s))" % username
        results = self.search(query, attributes=[])
        if len(results) > 0:
            return results[0]
        else:
            return None

    def get_group_members(self, group):
        """
        Gets all group members, including members who are indirect members, i.e
        recursively.  It is an iterative depth first search of a given group
        and all sub-objects of that group. iddfs was chosen becuase it less
        memory intensive than a breadth first search while still offering the
        same completeness and is simpler, in my mind, to understand than a true
        depth first search.
        """

        if not isinstance(group, str):
            raise TypeError

        user_list = []
        visited_objects = []

        result = self.search_groups(group, attributes=['member'])[0]
        visited_objects.append(result.dn)

        for obj in result.member:
            user_list.extend(self.visit_object(obj, visited_objects))
        return user_list

    def visit_object(self, obj, visited_objects):
        """
        The second half of the iddfs that does the iteration and recursion on
        the child members of the group being searched.
        """

        if not isinstance(visited_objects, list):
            raise TypeError

        user_list = []
        if obj not in visited_objects:
            query = "(objectClass=*)"
            result = self.search(query,
                                 base=obj,
                                 scope=ldap.SCOPE_BASE,
                                 attributes=[])[0]

            if 'person' in result.objectClass:
                user_list.extend(result.sAMAccountName)
            elif hasattr(result, 'member'):
                for child_obj in result.member:
                    user_list.extend(self.visit_object(child_obj, visited_objects))

            visited_objects.append(result.dn)
        return user_list


if __name__ == "__main__":
    l = LDAP("wwu")
    query = "*webteam*"
    print("Searching groups for '%s':" % query)
    results = l.search_groups(query)
    print("Found:")
    print(results)

    query = "Firass Asad"
    print("Searching people for '%s':" % query)
    results = l.search_people(query)
    print("Found:")
    print(results)

    username = "lohrb"
    print("Get person by username: %s" % username)
    person = l.get_person_by_username(username)
    print(person)
