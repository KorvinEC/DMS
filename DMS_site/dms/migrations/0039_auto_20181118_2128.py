# Generated by Django 2.1.2 on 2018-11-18 21:28

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('dms', '0038_commentary_document'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='profile',
            name='user',
        ),
        migrations.DeleteModel(
            name='Profile',
        ),
    ]
