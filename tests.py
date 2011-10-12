"""
Unit tests for LDAP authorization and authentication.
"""
from django.contrib.auth.models import User
from django.test import TestCase

from wwu_housing.ldapauth import LDAP
from utils import django_user_set_for_ldap_group, get_users_by_distinguished_name


class LDAPTestCase(TestCase):
    def setUp(self):
        self.ldap = LDAP("wwu")

    def test_search_groups(self):
        self.ldap = LDAP("wwu")
        query = "*webteam*"
        results = self.ldap.search_groups(query)
        self.assertTrue(len(results) > 0)

    def test_search_people(self):
        query = "Firass Asad"
        results = self.ldap.search_people(query)
        self.assertEquals(len(results), 1)

    def test_get_person_by_username(self):
        username = "lohrb"
        person = self.ldap.get_person_by_username(username)
        self.assertEquals(username, person.sAMAccountName[0])

    def test_get_token_groups_by_user(self):
        username = "asadf"
        person = self.ldap.get_person_by_username(username)
        token_groups = self.ldap.get_token_groups_by_dn(person.dn)
        self.assertTrue(len(token_groups) > 0)
        self.assertTrue(token_groups[1] is not None, token_groups)
        self.assertTrue(token_groups[1].startswith("grp"), token_groups)


class LDAPResultTestCase(TestCase):
    def setUp(self):
        self.ldap = LDAP("wwu")

    def test_get_token_groups_by_user(self):
        username = "asadf"
        person = self.ldap.get_person_by_username(username)
        self.assertTrue(len(person.groups) > 0)
        self.assertTrue(person.groups[1] is not None, person.groups)
        self.assertTrue(person.groups[1].startswith("grp"), person.groups)


class UtilsTestCase(TestCase):
    """
    Tests for LDAP utils.
    """
    fixtures = ["django_users_staff.json"]

    def test_get_users_by_distinguished_name(self):
        user = User.objects.create_user(
            username="test0r",
            password="!",
            email="test0r@test0r.com"
        )
        user.first_name = "Testy"
        user.last_name = "McTestorson"
        user.save()

        self.assertEquals(
            get_users_by_distinguished_name(["CN=test0r,OU=wwu"])[0],
            user
        )
        self.assertEquals(
            get_users_by_distinguished_name(["CN=Testy McTestorson,OU=wwu"])[0],
            user
        )
        self.assertEquals(
            get_users_by_distinguished_name(["CN=fakeuser,OU=wwu"]).count(),
            User.objects.none().count()
        )

    def test_django_user_set_for_ldap_group(self):
        # Test a group known to have users.
        user_set = django_user_set_for_ldap_group("grp.housing.roles.residence-life.resident-director")
        self.assertTrue(len(user_set) > 0)
        self.assertTrue(isinstance(user_set[0], User))

        # Test a fake group.
        self.assertRaises(
            IndexError,
            django_user_set_for_ldap_group,
            "grp.housing.roles.fakerole"
        )
