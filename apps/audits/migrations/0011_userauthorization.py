from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [
        ('audits', '0010_merge_20260901_1511'),
        ('users', '0007_merge_0005_ukey_0006_user_ukey_sn'),
    ]

    operations = [
        migrations.CreateModel(
            name='UserAuthorization',
            fields=[],
            options={
                'verbose_name': 'User authorization',
                'proxy': True,
                'default_permissions': ('view',),
                'indexes': [],
                'constraints': [],
            },
            bases=('users.user',),
        ),
    ]
