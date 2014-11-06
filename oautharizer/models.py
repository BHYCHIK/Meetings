# -*- coding: utf-8 -*-
from django.db import models


# Create your models here.
class User(models.Model):
    class Meta():
        db_table = 'user'
    login = models.CharField(max_length=64, verbose_name="Логин", unique=True)
    password = models.CharField(max_length=32, verbose_name="Хэш пароля")
    age = models.PositiveSmallIntegerField()
    phone = models.CharField(max_length=32)
    email = models.EmailField(max_length=96, unique=True)
    name = models.CharField(max_length=128)


class ClientApplication(models.Model):
    class Meta():
        db_table = 'client_application'
    application_name = models.CharField(max_length=255, verbose_name='Название приложения')
    application_secret = models.CharField(max_length=32, verbose_name='Секретный ключ приложентя')
    application_id = models.IntegerField(primary_key=True, verbose_name='Номер приложения')
    redirect_domain = models.CharField(max_length=1024)
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

class RefreshTokens(models.Model):
    class Meta():
        db_table = 'refresh_tokens'
    refresh_token = models.CharField(max_length=64)
    user = models.ForeignKey(User)
    application = models.ForeignKey(ClientApplication)


class Place(models.Model):
    class Meta():
        db_table = 'place'
    pass
    name = models.CharField(max_length=128)
    x_coord = models.FloatField()
    y_coord = models.FloatField()


class Plan(models.Model):
    class Meta():
        db_table = 'plan'
    user = models.ForeignKey(User)
    title = models.CharField(max_length=128)
    body = models.TextField()
    place = models.ForeignKey(Place)
    date = models.DateTimeField()