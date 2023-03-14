import uuid

from requests import Response

import demistomock as demisto
from CommonServerPython import *
import json
import urllib3
from typing import Any, Dict, Tuple, List, Optional, Union, cast

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
VENDOR = 'hello'
PRODUCT = 'world'

''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the service API
    This Client implements API calls, and does not contain any Demisto logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this HelloWorld implementation, no special attributes defined
    """

    def search_events(self, prev_id, alert_status):
        """
        Searches for HelloWorld alerts using the '/get_alerts' API endpoint.
        All the parameters are passed directly to the API as HTTP POST parameters in the request
        Args:
            prev_id: previous id that was fetched.
            alert_status:
        Returns:
            dict: the next event
        """
        return [{
            'id': prev_id + 1,
            'created_time': datetime.now().isoformat(),
            'description': f'This is test description {prev_id + 1}',
            'alert_status': alert_status,
            'custom_details': {
                               'triggered_by_name': f'Name for id: {prev_id + 1}',
                               'triggered_by_uuid': str(uuid.uuid4()),
                               'type': 'customType'
            }
        }]


def test_module(client: Client, params: Dict[str, Any], first_fetch_time: int) -> str:
    """
    Tests API connectivity and authentication'
    When 'ok' is returned it indicates the integration works like it is supposed to and connection to the service is
    successful.
    Raises exceptions if something goes wrong.
    Args:
        client (Client): HelloWorld client to use.
        params (Dict): Integration parameters.
        first_fetch_time (int): The first fetch time as configured in the integration params.
    Returns:
        str: 'ok' if test passed, anything else will raise an exception and will fail the test.
    """

    try:
        alert_status = params.get('alert_status', None)

        fetch_events(
            client=client,
            last_run={},
            first_fetch_time=first_fetch_time,
            alert_status=alert_status,
        )

    except Exception as e:
        if 'Forbidden' in str(e):
            return 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e

    return 'ok'


def get_events(client, alert_status):
    events = client.search_events(
        prev_id=0,
        alert_status=alert_status
    )
    hr = tableToMarkdown(name='Test Event', t=events)
    return events, CommandResults(readable_output=hr)


def fetch_events(client: Client, last_run: Dict[str, int],
                 first_fetch_time: Optional[int], alert_status: Optional[str]
                 ):
    """
    Args:
        client (Client): HelloWorld client to use.
        last_run (dict): A dict with a key containing the latest event created time we got from last fetch.
        first_fetch_time(int): If last_run is None (first time we are fetching), it contains the timestamp in
            milliseconds on when to start fetching events.
        alert_status (str): status of the alert to search for. Options are: 'ACTIVE' or 'CLOSED'.
    Returns:
        dict: Next run dictionary containing the timestamp that will be used in ``last_run`` on the next fetch.
        list: List of events that will be created in XSIAM.
    """
    prev_id = last_run.get('prev_id', None)
    if not prev_id:
        prev_id = 0

    events = client.search_events(
        prev_id=prev_id,
        alert_status=alert_status
    )
    demisto.info(f'Fetched event with id: {prev_id + 1}.')

    # Save the next_run as a dict with the last_fetch key to be stored
    next_run = {'prev_id': prev_id + 1}
    demisto.info(f'Setting next run {next_run}.')
    return next_run, events


''' MAIN FUNCTION '''


def main() -> None:
    """
    main function, parses params and runs command functions
    """

    params = demisto.params()
    args = demisto.args()
    command = demisto.command()
    api_key = params.get('apikey', {}).get('password')
    base_url = urljoin(params.get('url'), '/api/v1')
    verify_certificate = not params.get('insecure', False)

    # How much time before the first fetch to retrieve events
    first_fetch_time = arg_to_datetime(
        arg=params.get('first_fetch', '3 days'),
        arg_name='First fetch time',
        required=True
    )
    first_fetch_timestamp = int(first_fetch_time.timestamp()) if first_fetch_time else None
    assert isinstance(first_fetch_timestamp, int)
    proxy = params.get('proxy', False)
    alert_status = params.get('alert_status', None)

    demisto.debug(f'Command being called is {command}')
    try:
        headers = {
            'Authorization': f'Bearer {api_key}'
        }
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy)

        if command == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client, params, first_fetch_timestamp)
            return_results(result)

        elif command in ('hello-world-get-events', 'fetch-events'):
            if command == 'hello-world-get-events':
                should_push_events = argToBoolean(args.pop('should_push_events'))
                events, results = get_events(client, alert_status)
                return_results(results)

            else:  # command == 'fetch-events':
                should_push_events = True
                last_run = demisto.getLastRun()
                next_run, events = fetch_events(
                    client=client,
                    last_run=last_run,
                    first_fetch_time=first_fetch_timestamp,
                    alert_status=alert_status,
                )
                # saves next_run for the time fetch-events is invoked
                demisto.setLastRun(next_run)

            if should_push_events:
                send_events_to_xsiam(
                    events,
                    vendor=VENDOR,
                    product=PRODUCT
                )

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()