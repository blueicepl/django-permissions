# -*- coding: utf-8 -*-
# Generated by Django 1.11.18 on 2019-01-21 08:44
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('permissions', '0001_initial'),
    ]

    operations = [
        migrations.AddIndex(
            model_name='principalrolerelation',
            index=models.Index(fields=[b'user_id', b'group_id', b'role_id', b'content_type_id'], name='permissions_user_id_cf67e1_idx'),
        ),
        migrations.AddIndex(
            model_name='principalrolerelation',
            index=models.Index(fields=[b'user_id', b'content_type_id'], name='permissions_user_id_c86869_idx'),
        ),
    ]
