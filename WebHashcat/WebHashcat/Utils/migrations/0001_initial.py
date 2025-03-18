# Generated by Django 2.1.2 on 2019-02-17 08:02

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('Hashcat', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='Lock',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('lock_ressource', models.CharField(max_length=30)),
                ('hashfile', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='Hashcat.Hashfile')),
            ],
        ),
        migrations.CreateModel(
            name='Task',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('time', models.DateTimeField()),
                ('message', models.TextField()),
            ],
        ),
    ]
