from django.shortcuts import render, render_to_response, redirect
from django.core.context_processors import csrf
from django.db import IntegrityError, transaction
from django.http.response import Http404, HttpResponse
from django.views.decorators.csrf import csrf_exempt
import hashlib
import models
import random
import string

# Create your views here.

@csrf_exempt
def get_my_age(request):
    if 'access_token' not in request.GET:
        raise Http404

    access_obj = models.ActiveTokens.objects.filter(access_token=request.GET['access_token'])
    if access_obj.count() != 1:
        raise Http404

    return HttpResponse(access_obj[0].user.age)

def logout(request):
    if 'user_id' in request.session:
        del request.session['user_id']
    return redirect('/oautharizer/login/')

def _gen_rnd_str(length):
    return ''.join(random.choice(string.ascii_lowercase + string.digits) for x in xrange(length))

#?client_id=CLIENT-ID&client_secret=CLIENT-SECRET
# &grand_type=authorization_code&redirect_uri=REDIRECT-URI&code=CODE
@csrf_exempt
def oauth_client_step(request):
    client_id = request.GET.get('client_id')
    client_secret = request.GET.get('client_secret')
    redirect_uri = request.GET.get('redirect_uri')
    code = request.GET.get('code')
    grant_type = request.GET.get('grant_type')

    print client_id
    print redirect_uri
    print client_secret
    print code
    print grant_type

    if (client_id is None) or (redirect_uri is None) \
            or (grant_type is None) or (grant_type != 'authorization_code') \
            or (client_secret is None) or (code is None):
        raise Http404

    print 'checked'

    app = models.ClientApplication.objects.filter(application_id=client_id,
                                                  application_secret=client_secret)
    if app.count() != 1:
        raise Http404

    db_req = models.ProcessingRequest.objects.filter(application=app, pk=code,
                                                     redirect_uri=redirect_uri)

    if db_req.count() != 1:
        raise Http404

    access_token_obj = models.ActiveTokens()
    access_token_obj.access_token = _gen_rnd_str(64)
    access_token_obj.user = db_req[0].user
    access_token_obj.save()

    db_req[0].delete()

    return HttpResponse(access_token_obj.access_token)

#?client_id=CLIENT-ID&redirect_uri=REDIRECT-URI&response_type=code
@csrf_exempt
def oauth_owner_step(request):
    client_id = request.GET.get('client_id')
    redirect_uri = request.GET.get('redirect_uri')
    response_type = request.GET.get('response_type')
    if (client_id is None) or (redirect_uri is None) or (response_type is None) or (response_type != 'code'):
        raise Http404
    if request.POST:
        user = models.User.objects.filter(login=request.POST.get('login'),
                                          password=hashlib.md5(request.POST.get('password')).hexdigest())
        if user.count() != 1:
            return render_to_response('loginerr.html')
        request.session['user_id'] = user[0].pk
    if 'user_id' not in request.session:
        ctx = {}
        ctx.update(csrf(request))
        ctx['redirect_path'] = '?client_id={0}&redirect_uri={1}&response_type=code'.format(client_id, redirect_uri)
        return render_to_response('login.html', ctx)

    processing_request = models.ProcessingRequest()
    processing_request.redirect_uri = redirect_uri
    processing_request.application = models.ClientApplication.objects.get(pk=client_id)
    processing_request.user = models.User.objects.get(pk=request.session['user_id'])
    processing_request.save()

    return redirect('{0}?code={1}'.format(redirect_uri, processing_request.pk))

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