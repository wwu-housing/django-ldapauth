"""
Unit tests for LDAP authorization and authentication.
"""

from django.test import TestCase

from wwu_housing.ldapauth import LDAP


class LDAPTest(TestCase):
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
