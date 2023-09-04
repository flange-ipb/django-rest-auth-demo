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
from django.urls import path, include
from drf_yasg import openapi
from drf_yasg.views import get_schema_view
from rest_framework import permissions

from project.app.views import not_found

schema_view = get_schema_view(
    openapi.Info(title="My API", default_version='v1'),
    public=True,
    permission_classes=(permissions.AllowAny,),
)

urlpatterns = [
    path('auth/', include('dj_rest_auth.urls')),
    path('auth/registration/', include('dj_rest_auth.registration.urls')),
    path('swagger<format>/', schema_view.without_ui(cache_timeout=0), name='schema-json'),
    path('swagger/', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
    path('redoc/', schema_view.with_ui('redoc', cache_timeout=0), name='schema-redoc'),

    # The view named 'password_reset_confirm' is only necessary to build the confirmation URL that is used in the
    # password reset email. It can be used to direct the client to an SPA's view which invokes the view
    # 'rest_password_reset_confirm' with the appropriate data.
    # See https://dj-rest-auth.readthedocs.io/en/stable/faq.html and
    # https://github.com/iMerica/dj-rest-auth/blob/master/demo/demo/urls.py
    path('spa/password-reset/confirm/<uid>/<token>', not_found, name='password_reset_confirm'),

    # Same argumentation as above: The SPA needs to invoke the 'rest_verify_email' view with the key as payload.
    path('spa/account-confirm-email/<key>', not_found, name='account_confirm_email'),
]
