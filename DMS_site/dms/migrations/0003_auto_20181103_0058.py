# Generated by Django 2.1.2 on 2018-11-02 21:58

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('dms', '0002_auto_20181102_1645'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='log',
            name='id_user_document',
        ),
        migrations.RemoveField(
            model_name='user_document',
            name='id_document',
        ),
        migrations.RemoveField(
            model_name='user_document',
            name='id_user',
        ),
        migrations.AddField(
            model_name='document',
            name='author',
            field=models.ForeignKey(default=1, on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL),
            preserve_default=False,
        ),
        migrations.DeleteModel(
            name='Log',
        ),
        migrations.DeleteModel(
            name='User_Document',
        ),
    ]