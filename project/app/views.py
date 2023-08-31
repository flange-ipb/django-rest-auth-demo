from django.http import Http404
from django.views.decorators.csrf import csrf_exempt


@csrf_exempt
def not_found(request, uid, token):
    raise Http404()
