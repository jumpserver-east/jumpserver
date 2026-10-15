import uuid

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        ('tickets', '0007_ticketflow_name_and_five_approval_levels'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='TicketRepairCode',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('digest', models.CharField(editable=False, max_length=64, unique=True)),
                ('used_at', models.DateTimeField(editable=False, null=True)),
                ('approver', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
                ('ticket', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='repair_codes', to='tickets.applyassetticket')),
            ],
            options={'default_permissions': ()},
        ),
    ]
