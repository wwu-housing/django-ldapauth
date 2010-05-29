import binascii
import ctypes
import ConfigParser
import ldap
import struct

def convert_binary_sid_to_str(sid):
    # Start building the string.
    sid_str = "S-"

    # Convert the binary string to hex. Remember the hex string represents
    # each byte of data with 2 characters, so the string is twice as long as
    # the data. Hence the need to multiply by two, as seen below.
    hex_str = binascii.hexlify(sid)
    byte_c = 0 #byte count

    # hex_str[0:2], first byte - revision
    substr = hex_str[byte_c:byte_c + 2]
    hex_data = ctypes.create_string_buffer(substr.decode('hex'), 2)
    sid_str += str(struct.unpack('H', hex_data)[0]) # Two bytes
    sid_str += "-"
    byte_c +=2

    # hex_str[2:4], second byte - number of dashes
    substr = hex_str[byte_c: byte_c + 2]
    hex_data = ctypes.create_string_buffer(substr.decode('hex'), 2)
    count = struct.unpack('H', hex_data)[0] # ditto, only two bytes
    byte_c +=2

    # hex_str[4:16], next six bytes - SECURITY_NT_AUTHORITY
    # This is freakin' ugly, a 6 byte string in big-endian format.
    # Which is, of course, different than the rest of the SID.
    substr = hex_str[byte_c:byte_c + (2*6)] # Two chars/byte, 6 bytes
    hex_data = ctypes.create_string_buffer(substr.decode('hex'), 6)
    sid_str += str(struct.unpack('>IH', hex_data)[1]) # Big endian
    byte_c += (2*6)

    # hex_str[16: the end of the string, based on the count]
    # Ok, now things are somewhat sane, get the rest of the SID.
    for i in range(0, count):
        sid_str += '-'
        substr = hex_str[byte_c:byte_c + (2*4)] #two chars/byte, 4 bytes
        hex_data = ctypes.create_string_buffer(substr.decode('hex'), 4)
        sid_str += str(struct.unpack('<I', hex_data)[0]) # Little endian
        byte_c += (2*4)

    return sid_str


class LDAPResult(object):
    """
    Represents a single LDAP result which is typically a dictionary of LDAP
    key/value pairs.

    This class allows values to be accessed as instance attributes named after
    the keys.
    """
    def __init__(self, result_tuple):
        self.dn, rows = result_tuple
        self.__dict__.update(**rows)

    def __unicode__(self):
        """
        Returns a display value for this result based on the common name.
        """
        if hasattr(self, "cn"):
            return u"".join(self.cn)
        else:
            return self.dn

    def __repr__(self):
        return "<%s: %s>" % (self.__class__.__name__, self.__unicode__())


class LDAP(object):
    conf_file = "/usr/local/etc/wwu_ldap.conf"

    def __init__(self, conf_section, scope=None):
        """
        Prepares the LDAP object for connecting to an LDAP service as defined in
        a configuration section of the LDAP configuration file.

        The conf_section defines a server, dn, bind password, and base for the
        LDAP service.

        Example usage for an LDAP configuration file with a "wwu" section:
        >>> l = LDAP("wwu")
        """
        if scope is None:
            self.scope = ldap.SCOPE_SUBTREE
        else:
            self.scope = scope

        config = ConfigParser.SafeConfigParser()
        config.read(self.conf_file)
        self.server = config.get(conf_section, "server")
        self.dn = config.get(conf_section, "dn")
        self.bindpw = config.get(conf_section, "bindpw")
        self.base = config.get(conf_section, "base")

    def bind(self):
        self.ldap = ldap.initialize(self.server)
        self.ldap.simple_bind(self.dn, self.bindpw)

    def unbind(self):
        self.ldap.unbind()

    def get_token_groups_by_user(self, user_base_dn):
        """
        Search on the base DN of the user to get the tokenGroups attribute.

        Token groups are binary ids for all groups a user belongs to in the AD
        tree.
        """
        query = "(objectClass=*)"
        attributes = ["tokenGroups"]
        results = self.ldap.search_s(user_base_dn, self.scope, query, attributes)
        result = LDAPSearchResult(results[0])
        tokenGroups = result.get_attr_values(attr[0])
        return tokenGroups

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

        return [LDAPResult(result_tuple) for result_tuple in results]

    def search_groups(self, query, attributes=None):
        query = "(&(objectClass=group)(cn=%s))" % query
        return self.search(query, attributes=attributes)

    def search_people(self, query, attributes=None):
        query = "(&(objectClass=person)(cn=%s))" % query
        return self.search(query, attributes=attributes)

    def get_person_by_username(self, username):
        query = "(&(objectClass=person)(sAMAccountName=%s))" % username
        results = self.search(query, attributes=[])
        if len(results) > 0:
            return results[0]
        else:
            return None


if __name__ == "__main__":
    l = LDAP("wwu")
    query = "*webteam*"
    print "Searching groups for '%s':" % query
    results = l.search_groups(query)
    print "Found:"
    print results

    query = "Firass Asad"
    print "Searching people for '%s':" % query
    results = l.search_people(query)
    print "Found:"
    print results

    username = "lohrb"
    print "Get person by username: %s" % username
    person = l.get_person_by_username(username)
    print person
