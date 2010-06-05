"""
Models for ldap authorization application.
"""
from django.db import models


class LdapGroup(models.Model):
    """
    Represents an Active Directory token group security identifier and its
    corresponding name.
    """
    sid = models.CharField(max_length=255, unique=True)
    name = models.CharField(max_length=255)
