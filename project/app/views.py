from allauth.socialaccount.providers.github.views import GitHubOAuth2Adapter
from allauth.socialaccount.providers.oauth2.client import OAuth2Client
from allauth.socialaccount.providers.orcid.views import OrcidOAuth2Adapter
from dj_rest_auth.registration.views import SocialLoginView
from django.http import Http404
from django.views.decorators.csrf import csrf_exempt


@csrf_exempt
def not_found(*args, **kwargs):
    raise Http404()


class GitHubLogin(SocialLoginView):
    adapter_class = GitHubOAuth2Adapter
    callback_url = "http://127.0.0.1:8000/spa/github/login/callback/"
    client_class = OAuth2Client


class ORCIDLogin(SocialLoginView):
    adapter_class = OrcidOAuth2Adapter
    callback_url = "http://a.localhost:8000/spa/orcid/login/callback/"
    client_class = OAuth2Client
