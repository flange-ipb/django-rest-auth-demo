from allauth.socialaccount.providers.github.views import GitHubOAuth2Adapter
from allauth.socialaccount.providers.oauth2.client import OAuth2Client
from allauth.socialaccount.providers.orcid.views import OrcidOAuth2Adapter
from dj_rest_auth.registration.views import SocialLoginView, SocialConnectView
from django.http import Http404
from django.views.decorators.csrf import csrf_exempt


@csrf_exempt
def not_found(*args, **kwargs):
    raise Http404()


class GitHubMixin:
    adapter_class = GitHubOAuth2Adapter
    client_class = OAuth2Client


class GitHubLogin(GitHubMixin, SocialLoginView):
    pass


class GitHubConnect(GitHubMixin, SocialConnectView):
    pass


class ORCIDMixin:
    adapter_class = OrcidOAuth2Adapter
    # TODO: remove when we have a proper hostname
    callback_url = "http://a.localhost:8000/spa/orcid/login/callback/"
    client_class = OAuth2Client


class ORCIDLogin(ORCIDMixin, SocialLoginView):
    pass


class ORCIDConnect(ORCIDMixin, SocialConnectView):
    pass
