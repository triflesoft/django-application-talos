# Generated by Django 2.0.3 on 2018-04-02 10:46

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('talos', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='basicidentitydirectory',
            name='OTP_credential_directory',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='otp_identity_directories', to='talos.OneTimePasswordCredentialDirectory'),
        ),
    ]
