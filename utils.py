import re
from django.contrib.auth.models import Group, User
from django.db.models import Q
from wwu_housing.ldapauth import LDAP

def django_user_set_for_ldap_group(group):
    """
    Return a django User model's queryset representing all the users in `group`.

    `group` can be either a string that is the name of a group, or a Django
    Group model instance.
    """
    if isinstance(group, basestring):
        group_name = group
    elif isinstance(group, Group):
        group_name = group.name
    else:
        raise TypeError("""\
The `group` argument must be either a string thatis the name of a group, or a
Django Group model instance.\
""")

    cn_re = re.compile(r'CN=(.*?),')
    def get_cn(member):
        """
        Parse out the username/full-name of a matched group member from
        LDAP.

        Here are some examples of what LDAP members look like:

        "CN=Lafayette Something,OU=employees,..."
        "CN=fitzgen,OU=students,..."
        """
        return cn_re.findall(member)[0]

    def get_django_userset_from_ldap_member_list(members):
        """
        Takes a list of unparsed member results from an LDAP query and returns a
        Django User queryset for all of those group members.
        """
        members = map(get_cn, members)
        full_names = set([m for m in members if len(m.split(" ")) == 2])
        user_names = set(members).difference(full_names)
        full_names = [m.split(" ") for m in full_names]

        def join_one_query(query_obj, name_pair):
            """
            Join one [first, last] name pair queryset to the query object.
            """
            first = name_pair[0]
            last = name_pair[1]
            return query_obj | Q(first_name=first, last_name=last)

        return User.objects.filter(reduce(join_one_query,
                                          full_names,
                                          Q(username__in=user_names)))

    return get_django_userset_from_ldap_member_list(
        LDAP("wwu").search_groups(
            group_name,
            ["member"]
        )[0].member
    )

