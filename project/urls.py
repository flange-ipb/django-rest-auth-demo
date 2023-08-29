"""
URL configuration for project project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.urls import path, include, re_path
from django.views.generic import TemplateView
from drf_yasg import openapi
from drf_yasg.views import get_schema_view
from rest_framework import permissions

schema_view = get_schema_view(
    openapi.Info(title="My API", default_version='v1'),
    public=True,
    permission_classes=(permissions.AllowAny,),
)

urlpatterns = [
    # The view name 'password_reset_confirm' is only used to build the confirmation URL that is used in the password
    # reset email. This can be used to direct the client to an SPA view which invokes the view
    # 'rest_password_reset_confirm'.
    # See https://dj-rest-auth.readthedocs.io/en/stable/faq.html and
    # https://github.com/iMerica/dj-rest-auth/blob/master/demo/demo/urls.py
    path('auth/password-reset/confirm/<uidb64>/<token>', TemplateView.as_view(), name='password_reset_confirm'),

    path('auth/', include('dj_rest_auth.urls')),
    path('auth/registration/', include('dj_rest_auth.registration.urls')),
    path('swagger<format>/', schema_view.without_ui(cache_timeout=0), name='schema-json'),
    path('swagger/', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
    path('redoc/', schema_view.with_ui('redoc', cache_timeout=0), name='schema-redoc'),
]
