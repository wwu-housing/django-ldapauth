from django.contrib.auth.models import User

from wwu_housing.data import Person

from wwu_housing.auth.models import User
from wwu_housing.ldapauth import LDAP

from django.core.management.base import NoArgsCommand


class Command(NoArgsCommand):
    def handle_noargs(self, **options):
        wwu = LDAP("wwu")

        user_list = set()

        groups = wwu.search_groups("grp.housing.communities.*")

        for group in groups:
                try:
                    user_list.update(set(wwu.get_group_members(group.cn[0])))
                except:
                    #there are issues for groups that no longer really have a function like NY apartments
                    pass
        bad_users = []

        for username in user_list:
                has_role = reduce(lambda sofar, group_name: True if "grp.housing.roles" in group_name else sofar, wwu.get_person_by_username(username).groups, False)
                if not has_role:
                        bad_users.append(username)

        print bad_users
