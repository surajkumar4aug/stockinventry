# Generated by Django 4.2.2 on 2023-07-03 15:22

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('user', '0007_alter_user_id_proof_alter_user_staff_id'),
    ]

    operations = [
        migrations.AlterField(
            model_name='user',
            name='address',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to='user.address'),
        ),
    ]