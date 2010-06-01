"""
Unit tests for LDAP authorization and authentication.
"""

from django.test import TestCase

from wwu_housing.ldapauth import LDAP


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
