import pytest
from rest_framework.test import APIClient, RequestsClient


@pytest.fixture
def api_client():
    return APIClient()


@pytest.fixture
def requests_client():
    return RequestsClient()
