# -*- coding: utf-8 -*-
from django.db import models

# Create your models here.
class User(models.Model):
    class Meta():
        db_table = 'user'
    login = models.CharField(max_length=64, verbose_name="Логин", unique=True)
    password = models.CharField(max_length=32, verbose_name="Хэш пароля")
    age = models.PositiveSmallIntegerField()

class ClientApplication(models.Model):
    class Meta():
        db_table = 'client_application'
    application_name = models.CharField(max_length=255, verbose_name='Название приложения')
    application_secret = models.CharField(max_length=32, verbose_name='Секретный ключ приложентя')
    application_id = models.IntegerField(primary_key=True, verbose_name='Номер приложения')
    application_author = models.ForeignKey(User)

class ProcessingRequest(models.Model):
    class Meta():
        db_table = 'processing_requests'
    application = models.ForeignKey(ClientApplication)
    user = models.ForeignKey(User)
    creation_time = models.DateTimeField(auto_now=True)
    redirect_uri = models.URLField()

class ActiveTokens(models.Model):
    class Meta():
        db_table = 'active_tokens'
    access_token = models.CharField(max_length=64)
    user = models.ForeignKey(User)
    creation_time = models.DateTimeField(auto_now=True)