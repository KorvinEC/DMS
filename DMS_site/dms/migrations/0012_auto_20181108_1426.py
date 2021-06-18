# Generated by Django 2.1.2 on 2018-11-08 11:26

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('dms', '0011_auto_20181104_2100'),
    ]

    operations = [
        migrations.AddField(
            model_name='log',
            name='project',
            field=models.ForeignKey(blank=True, default=1, on_delete=django.db.models.deletion.CASCADE, to='dms.Project'),
            preserve_default=False,
        ),
        migrations.AlterField(
            model_name='log',
            name='document',
            field=models.ForeignKey(blank=True, on_delete=django.db.models.deletion.CASCADE, to='dms.Document'),
        ),
    ]