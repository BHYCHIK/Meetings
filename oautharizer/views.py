from django.shortcuts import render, render_to_response, redirect
from django.core.context_processors import csrf
from django.db import IntegrityError
from django.http.response import Http404, HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.core.exceptions import ObjectDoesNotExist
import hashlib
import models
import random
import string
import json
import config
import time

# Create your views here.


def json_result_decorator(view_func):
    def wrapper(request):
        print 'json_result_decorator'
        result = view_func(request)
        result['Content-Type'] = 'application/json;charset=UTF-8'
        return result
    return wrapper


def no_cache_decorator(view_func):
    def wrapper(request):
        print 'no_cache_decorator'
        result = view_func(request)
        result['Cache-Control'] = 'no-store'
        result['Pragma'] = 'no-cache'
        return result
    return wrapper


def token_checker_decorator(view_func):
    print 'no_cache_decorator'
    @no_cache_decorator
    @json_result_decorator
    def wrapper(request):
        reply = dict()
        if 'access_token' not in request.GET:
            reply['error_code'] = 3
            reply['error_description'] = 'Access denied'
            return HttpResponse(json.dumps(reply))

        access_obj = models.ActiveTokens.objects.filter(access_token=request.GET['access_token'])

        if access_obj.count() != 1:
            reply['error_code'] = 3
            reply['error_description'] = 'Access denied'
            return HttpResponse(json.dumps(reply))

        dif_time = int(time.time()) - time.mktime(access_obj[0].creation_time.timetuple())
        if dif_time < 0:
            print "STRANGE THING HAPPEND"
            raise Http404
        if dif_time > config.token_expire_time:
            reply['error_code'] = 3
            reply['error_description'] = 'Access denied'
            return HttpResponse(json.dumps(reply))

        return view_func(request, access_obj)

    return wrapper

@json_result_decorator
def get_stats(request):
    reply = dict()
    reply['total_users'] = models.User.objects.all().count()
    reply['total_apps'] = models.ClientApplication.objects.all().count()
    reply['active_sessions'] = models.ActiveTokens.objects.all().count()
    return HttpResponse(json.dumps(reply))


@json_result_decorator
@token_checker_decorator
def about_me(request, access_obj=None):
    reply = dict()
    reply['id'] = access_obj[0].user.pk
    reply['name'] = access_obj[0].user.name
    reply['phone'] = access_obj[0].user.phone
    reply['login'] = access_obj[0].user.login
    reply['age'] = access_obj[0].user.age
    return HttpResponse(json.dumps(reply))


def logout(request):
    if 'user_id' in request.session:
        del request.session['user_id']
    return redirect('/oautharizer/login/')


def _gen_rnd_str(length):
    return ''.join(random.choice(string.ascii_lowercase + string.digits) for x in xrange(length))


@csrf_exempt
@json_result_decorator
@no_cache_decorator
def oauth_client_step(request):
    client_id = request.POST.get('client_id')
    client_secret = request.POST.get('client_secret')
    redirect_uri = request.POST.get('redirect_uri')
    code = request.POST.get('code')
    grant_type = request.POST.get('grant_type')

    reply = dict()

    if (client_id is None) or (redirect_uri is None) \
            or (grant_type is None) or (grant_type != 'authorization_code') \
            or (client_secret is None) or (code is None):
        reply['error_code'] = 1
        reply['error_description'] = 'Bad request'
        return HttpResponse(json.dumps(reply))

    app = models.ClientApplication.objects.filter(application_id=client_id,
                                                  application_secret=client_secret)
    if app.count() != 1:
        reply['error_code'] = 2
        reply['error_description'] = 'No such application'
        return HttpResponse(json.dumps(reply))

    db_req = models.ProcessingRequest.objects.filter(application=app, pk=code,
                                                     redirect_uri=redirect_uri)

    if db_req.count() != 1:
        reply['error_code'] = 3
        reply['error_description'] = 'No such code'
        return HttpResponse(json.dumps(reply))

    db_req = db_req[0]

    dif_time = int(time.time()) - time.mktime(db_req.creation_time.timetuple())
    if dif_time < 0:
        print "STRANGE THING HAPPEND"
        raise Http404

    if dif_time > config.code_valid_time:
        reply['error_code'] = 3
        reply['error_description'] = 'No such code'
        return HttpResponse(json.dumps(reply))

    access_token_obj = models.ActiveTokens()
    access_token_obj.access_token = _gen_rnd_str(64)
    access_token_obj.user = db_req.user
    access_token_obj.save()

    db_req.delete()

    reply['access_token'] = access_token_obj.access_token
    reply['token_type'] = 'bearer'
    reply['expires_in'] = config.token_expire_time
    reply['user_id'] = access_token_obj.user.id
    response_object = HttpResponse(json.dumps(reply))
    return response_object


#?client_id=CLIENT-ID&redirect_uri=REDIRECT-URI&response_type=code
def oauth_owner_step(request):
    client_id = request.GET.get('client_id')
    redirect_uri = request.GET.get('redirect_uri')
    response_type = request.GET.get('response_type')
    user = None
    if (client_id is None) or (redirect_uri is None) or (response_type is None) or (response_type != 'code'):
        raise Http404
    if request.POST and ('login' in request.POST):
        user = models.User.objects.filter(login=request.POST.get('login'),
                                          password=hashlib.md5(request.POST.get('password')).hexdigest())
        if user.count() != 1:
            return render_to_response('loginerr.html')
        user = user[0]
        request.session['user_id'] = user.pk

    application = None
    try:
        application = models.ClientApplication.objects.get(pk=client_id)
    except ObjectDoesNotExist:
        raise Http404

    if 'user_id' not in request.session:
        ctx = {}
        ctx.update(csrf(request))
        ctx['redirect_path'] = \
            '?client_id={0}&redirect_uri={1}&response_type=code{2}{3}'.\
            format(client_id,
                   redirect_uri,
                   '&state=' if 'state' in request.GET else '',
                   request.GET['state'] if 'state' in request.GET else '')
        return render_to_response('login.html', ctx)

    if user is None:
        user = models.User.objects.get(pk=request.session.get('user_id'))

    if 'allow_remote_login' not in request.POST:
        ctx = {}
        ctx.update(csrf(request))
        ctx['appname'] = application.application_name
        ctx['username'] = user.login
        ctx['redirect_path'] = \
            '?client_id={0}&redirect_uri={1}&response_type=code{2}{3}'.\
            format(client_id,
                   redirect_uri,
                   '&state=' if 'state' in request.GET else '',
                   request.GET['state'] if 'state' in request.GET else '')
        return render_to_response('allow_login.html', ctx)

    if request.POST['allow_remote_login'] == '1':

        processing_request = models.ProcessingRequest()
        processing_request.redirect_uri = redirect_uri
        processing_request.application = models.ClientApplication.objects.get(pk=client_id)
        processing_request.user = models.User.objects.get(pk=request.session['user_id'])
        processing_request.save()

        return redirect('{0}?code={1}{2}{3}'.format(redirect_uri, processing_request.pk,
                        '&state=' if 'state' in request.GET else '',
                        request.GET['state'] if 'state' in request.GET else ''))
    else:
        return redirect('{0}?error=1&error_decription={1}{2}{3}'.format(redirect_uri, 'login_not_allowed',
                        '&state=' if 'state' in request.GET else '',
                        request.GET['state'] if 'state' in request.GET else ''))


def myapps(request):
    if 'user_id' not in request.session:
        return redirect('/oautharizer/login/')
    user = models.User.objects.get(pk=request.session['user_id'])
    if request.POST:
        new_app = models.ClientApplication()
        new_app.application_author = user
        new_app.application_name = request.POST.get('appname')
        new_app.application_secret = _gen_rnd_str(32)
        new_app.save()
    ctx = dict()
    ctx.update(csrf(request))
    ctx['login'] = user.login
    ctx['apps'] = models.ClientApplication.objects.filter(application_author=user)
    return render_to_response('index.html', ctx)


def login(request):
    if request.POST:
        user = models.User.objects.filter(login=request.POST.get('login'),
                                          password=hashlib.md5(request.POST.get('password')).hexdigest())
        if user.count() != 1:
            return render_to_response('loginerr.html')
        request.session['user_id'] = user[0].pk
        return redirect('/oautharizer/')
    ctx = {}
    ctx.update(csrf(request))
    ctx['redirect_path'] = '.'
    return render_to_response('login.html', ctx)


def register(request):
    if request.POST:
        new_user = models.User()
        new_user.login = request.POST.get('login')
        new_user.password = hashlib.md5(request.POST.get('password')).hexdigest()
        new_user.age = request.POST.get('age')
        new_user.phone = request.POST.get('phone')
        new_user.email = request.POST.get('email')
        new_user.name = request.POST.get('name')
        try:
            new_user.save()
        except IntegrityError, e:
            return render_to_response('regerror.html', {'error_text':e.message})
        except Exception, e:
            raise e
        request.session['user_id'] = new_user.pk
        return redirect('/oautharizer/')
    ctx = {}
    ctx.update(csrf(request))
    return render_to_response('register.html', ctx)