# Generated by Django 2.1.2 on 2018-11-04 18:00

from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('dms', '0010_project_project_name'),
    ]

    operations = [
        migrations.AlterField(
            model_name='project',
            name='documents',
            field=models.ManyToManyField(blank=True, to='dms.Document'),
        ),
        migrations.AlterField(
            model_name='project',
            name='users',
            field=models.ManyToManyField(blank=True, to=settings.AUTH_USER_MODEL),
        ),
    ]
