# Generated by Django 2.0.3 on 2018-04-24 07:52

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('talos', '0006_phonesmsvalidationtoken_salt'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='validationtoken',
            name='email',
        ),
        migrations.AddField(
            model_name='validationtoken',
            name='identifier',
            field=models.CharField(choices=[('email', 'Email'), ('phone', 'Phone'), ('undefined', 'Undefined')], default='undefined', editable=False, max_length=255),
        ),
        migrations.AddField(
            model_name='validationtoken',
            name='identifier_value',
            field=models.CharField(max_length=255, null=True),
        ),
    ]
