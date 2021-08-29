import pytest
from fastapi.testclient import TestClient
from mpmm import api


@pytest.fixture()
def test_client():
    return TestClient(api)


def test_get_station_config(test_client):
    response = test_client.get("/station")

    EXPECTED_KEYS = [
        "callsign",
        "location",
        "locator",
        "operators",
        "interfaces",
        "remotes",
        "messages"
    ]

    assert response.status_code == 200
    for key in EXPECTED_KEYS:
        assert key in response.json().keys()
