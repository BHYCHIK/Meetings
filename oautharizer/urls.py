from django.conf.urls import patterns, include, url

urlpatterns = patterns('',
    # Examples:
    # url(r'^$', 'Meetings.views.home', name='home'),
    # url(r'^blog/', include('blog.urls')),
    url(r'^$', 'oautharizer.views.myapps'),
    url(r'^register/', 'oautharizer.views.register'),
    url(r'^login/', 'oautharizer.views.login'),
    url(r'^logout/', 'oautharizer.views.logout'),
    url(r'^api/authorize/', 'oautharizer.views.oauth_owner_step'),
    url(r'^api/access_token/', 'oautharizer.views.oauth_client_step'),
    url(r'^api/myage/', 'oautharizer.views.get_my_age')
)