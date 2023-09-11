from dj_rest_auth.views import UserDetailsView
from django.http import Http404
from django.views.decorators.csrf import csrf_exempt
from rest_framework.generics import RetrieveUpdateDestroyAPIView


@csrf_exempt
def not_found(*args, **kwargs):
    raise Http404()


class CustomUserDetailsView(UserDetailsView, RetrieveUpdateDestroyAPIView):
    pass
