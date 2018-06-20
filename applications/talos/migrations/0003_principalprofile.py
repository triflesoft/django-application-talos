# Generated by Django 2.0.3 on 2018-04-14 20:26

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('talos', '0002_onetimepasswordcredential_is_activated'),
    ]

    operations = [
        migrations.CreateModel(
            name='PrincipalProfile',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('is_secure', models.BooleanField(default=False)),
                ('principal', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='profile', to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]