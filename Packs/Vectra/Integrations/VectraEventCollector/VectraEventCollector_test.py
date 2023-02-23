"""
Unit tests for Vectra Event Collector
"""

import pytest
from unittest import mock
from VectraEventCollector import VectraClient, is_eod, test_module
from typing import Dict
import json
from datetime import datetime
from pathlib import Path

""" Constants """
BASE_URL = "mock://dev.vectra.ai"
PASSWORD = "9455w0rd"
client = VectraClient(url=BASE_URL, api_key=PASSWORD)


def load_json(path: Path):
    with open(path, mode="r", encoding="utf-8") as f:
        return json.load(f)


audits = load_json(Path("./test_data/search_detections.json"))
detections = load_json(Path("./test_data/audits.json"))
endpoints = load_json(Path("./test_data/endpoints.json"))
no_access_endpoints = load_json(Path("./test_data/endpoints_no_detection_audits.json"))

""" VectraClient Tests """


@pytest.mark.parametrize(
    "endpoints,expected",
    [
        ({"detections", f"{BASE_URL}/detections", "audits", f"{BASE_URL}/audits"}, True),
        ({"detections", f"{BASE_URL}/detections"}, False),
        ({"ep1", f"{BASE_URL}/ep1"}, False),
        ({}, False),
    ],
)
def test_auth(mocker: mock, endpoints: Dict[str, str], expected: bool):

    """
    Given:
        - A Vectra client.
    When:
        - Case A: The returned endpoints from the API root are the required ones.
        - Case B: The returned endpoints from the API root are missing 'audits'.
        - Case C: The returned endpoints from the API root are missing 'audits' and 'detections'.
        - Case D: The returned endpoints from the API root is empty.
    Then:
        - Case A: The authentication should succeed
        - Case B: The authentication should fail
        - Case C: The authentication should fail
        - Case D: The authentication should fail
    """

    mocker.patch.object(client, "get_endpoints", return_value=endpoints)
    endpoints = client.get_endpoints()

    assert all(ep in endpoints for ep in client.endpoints) == expected


def test_create_headers():

    """
    Given:
        - A Vectra client.
    When:
        - A token is supplied.
    Then:
        - Authentication headers match.
    """

    actual = client._create_headers()
    expected = {"Content-Type": "application/json", "Authorization": f"Token {PASSWORD}"}

    assert "Content-Type" in actual.keys()
    assert "Authorization" in actual.keys()

    assert actual == expected


@pytest.mark.parametrize(
    "endpoints,expected",
    [(endpoints, "ok"), (no_access_endpoints, "User doesn't have access to endpoints")],
)
def test_test_module(mocker: mock, endpoints: Dict[str, str], expected: str):
    """
    Given
            A dictionary of endpoints
    When
            Case A: Calling test-module with list of endpoints which include detections and audits
    Then
            Make sure that result succeds or not.
    """

    mocker.patch.object(client, "get_endpoints", return_value=endpoints)
    actual = test_module(client)
    assert expected in actual


""" Helper Functions Tests """


@pytest.mark.parametrize(
    "dt,expected",
    [
        (datetime(2023, 2, 22, 10, 55, 13), False),
        (datetime(2023, 2, 23, 00, 00, 13), False),
        (datetime(2023, 2, 23, 23, 59, 13), True),
    ],
)
def test_is_eod(dt: datetime, expected: bool):
    assert is_eod(dt) == expected