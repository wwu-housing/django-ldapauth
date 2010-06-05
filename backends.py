from django.contrib.auth.backends import ModelBackend
from django.contrib.auth.models import Permission

from wwu_housing.ldapauth import LDAP


class LDAPBackend(ModelBackend):
    """
    Django authorization backend which provides authorization through LDAP group
    membership.
    """
    def get_group_permissions(self, user):
        # Get locally stored group permissions.
        permissions_set = super(LDAPBackend, self).get_group_permissions(user)

        ldap = LDAP("wwu")
        ldap_person = ldap.get_person_by_username(user.username)
        groups = ldap_person.groups

        # The traditional ModelBackend fetches all Permission instances
        # associated with groups for which the current user is a member. This
        # backend doesn't rely on local user/group relationships so it queries
        # Permissions directly by group name instead of by group__user foreign
        # key relationship.
        if len(groups) > 0:
            permissions = Permission.objects \
                .filter(group__name__in=groups) \
                .values_list("content_type__app_label", "codename") \
                .order_by()
            permissions_set.update(set(["%s.%s" % (ct, name)
                                        for ct, name in permissions]))

        return permissions_set
