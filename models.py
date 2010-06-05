from django.db import models


class LdapGroup(models.Model):
    sid = models.CharField(max_length=255, unique=True)
    name = models.CharField(max_length=255)
