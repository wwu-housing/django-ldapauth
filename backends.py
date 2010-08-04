"""
Custom authorization backend for Django. Does not handle authentication.
"""
from ldap import OPERATIONS_ERROR

from django.contrib.auth.backends import ModelBackend
from django.contrib.auth.models import Permission
from django.core.cache import cache
from django.core.mail import mail_admins

from wwu_housing.ldapauth import LDAP


class LDAPBackend(ModelBackend):
    """
    Django authorization backend which provides authorization through LDAP group
    membership.
    """
    def get_group_permissions(self, user):
        """
        Updates the set of locally defined group permissions with all
        permissions available to the given user through their LDAP group
        membership.
        """
        # Get locally stored group permissions.
        permissions_set = super(LDAPBackend, self).get_group_permissions(user)

        try:
            key = "group_permissions_%s" % user.username
            groups = cache.get(key)

            # Explicitly test for None because the cache may have had a "hit"
            # for the given key and returned a value that would evaluate to
            # False (e.g., [] or "").
            if groups is None:
                ldap = LDAP("wwu")
                ldap_person = ldap.get_person_by_username(user.username)

                # Try to get the groups attribute from the ldap_person. If
                # ldap_person is None or doesn't have a groups attribute, the
                # groups value is just an empty list.
                groups = getattr(ldap_person, "groups", [])
                cache.set(key, groups)

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
        except OPERATIONS_ERROR, e:
            mail_admins("LDAP Operations Error", "%s" % str(e))

        return permissions_set
