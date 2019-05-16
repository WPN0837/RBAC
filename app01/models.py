from django.db import models

from permission.models import Role


# Create your models here.
class UserInfo(models.Model):
    username = models.CharField(max_length=20)
    pwd = models.CharField(max_length=20)
    role = models.ManyToManyField(Role, verbose_name='角色')

    def __str__(self):
        return self.username
