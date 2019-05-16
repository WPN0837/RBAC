# Generated by Django 2.1.7 on 2019-05-16 07:13

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('permission', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='UserInfo',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('username', models.CharField(max_length=20)),
                ('pwd', models.CharField(max_length=20)),
                ('role', models.ManyToManyField(to='permission.Role', verbose_name='角色')),
            ],
        ),
    ]
