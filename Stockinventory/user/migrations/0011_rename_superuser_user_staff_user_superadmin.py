# Generated by Django 4.2.2 on 2023-07-06 03:45

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('user', '0010_customerdetails_customer_id_customerdetails_gst_no'),
    ]

    operations = [
        migrations.RenameField(
            model_name='user',
            old_name='superuser',
            new_name='staff',
        ),
        migrations.AddField(
            model_name='user',
            name='superadmin',
            field=models.BooleanField(default=False),
        ),
    ]
