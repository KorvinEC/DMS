# Generated by Django 2.1.2 on 2018-11-17 17:58

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('dms', '0033_auto_20181117_1727'),
    ]

    operations = [
        migrations.AlterField(
            model_name='profile',
            name='image',
            field=models.ImageField(blank=True, upload_to='profile_image'),
        ),
    ]
