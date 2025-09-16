import json
import time
import traceback
from itertools import batched
from datetime import datetime, timedelta, UTC

import requests
from anyrun import RunTimeException
from anyrun.connectors import FeedsConnector

from .config import Config
from .utils import (
    get_env_variable,
    extract_indicator_data,
    get_severity,
    get_description
)

DATE_TIME_FORMAT = "%Y-%m-%d %H:%M:%S"


class AnyRunFeeds:
    """ Class - wrapper to interact with MS Defender and ANY.RUN REST API """
    def __init__(self, log, feed_fetch_depth: int) -> None:
        self._headers = None
        self._config = Config
        self._log = log

        self._feed_fetch_depth = feed_fetch_depth

        self._authenticate()

    def _authenticate(self):
        """
        Authenticates connector in MS Defender API
        """
        url = f'https://login.microsoftonline.com/{get_env_variable('AzureTenantID')}/oauth2/token'
        body = {
            'resource': self._config.DEFENDER_API_URL,
            'client_id': get_env_variable('AzureClientID'),
            'client_secret': get_env_variable('AzureClientSecret'),
            'grant_type': 'client_credentials',
        }
        response = self._make_request(method='POST', url=url, data=body)

        if response.status_code > 300:
            self._throw_error(
                f'Failed to authenticate at: {self._config.DEFENDER_API_URL}. Please, check your credentials.', response
            )

        self._headers = {
            'Authorization': f'Bearer {response.json().get('access_token')}',
            'Content-Type': 'application/json',
        }

    def process_enrichment(self) -> None:
        with FeedsConnector(
            api_key=get_env_variable('ANYRUN_Basic_auth_token'),
                integration=Config.VERSION
        ) as connector:
            connector.check_authorization()
            self._log.info('Successful credentials check.')
            self._log.info('Initialized IOCs enrichment.')

            self._delete_indicators()

            if new_indicators := self._get_indicators(connector):
                self._load_indicators(new_indicators)

    def _delete_indicators(self) -> None:
        if not (indicators := self._list_indicators_ids()):
            self._log.warning('No indicators found in Microsoft XDR.')
            return

        self._log.info(f'Found {len(indicators)} ANY.RUN indicators to delete.')

        url = f'{self._config.DEFENDER_API_URL}/api/indicators/BatchDelete'

        for chunk in batched(indicators, 500):
            payload = {'IndicatorIds': chunk}

            response = self._make_request('POST', url, json.dumps(payload))

            if response.status_code >= 300:
                self._throw_error('Failed to batch delete indicators in Microsoft XDR.', response)

        self._log.info('Indicators successfully deleted.')

    def _list_indicators_ids(self) -> list[str]:
        url = f"{self._config.DEFENDER_API_URL}/api/indicators?filter=title+eq+'IoC from ANY.RUN TI Feeds'"

        response = self._make_request('GET', url)

        if response.status_code >= 300:
            self._throw_error('Failed to fetch indicators from Microsoft XDR', response)

        return [indicator.get('id') for indicator in response.json().get('value')]


    def _get_indicators(self, connector: FeedsConnector) -> list[dict]:
        """
       Gets actual indicators using ANY.RUN TAXII STIX server

       :param indicator_type: ANY.RUN indicator type
       :return: List of the indicators
       """

        feeds = connector.get_taxii_stix(
            match_type='indicator',
            match_version='all',
            limit=10000,
            modified_after=(datetime.now(UTC) - timedelta(days=self._feed_fetch_depth)).strftime(DATE_TIME_FORMAT)
        )

        indicators = [feed for feed in feeds.get('objects')]

        if indicators:
            self._log.info(f'Found {len(indicators)} indicators.')
        else:
            self._log.warning(f'No indicators found in ANY.RUN TI.')

        return indicators

    def _load_indicators(self, indicators: list[dict]) -> None:
        url = f'{self._config.DEFENDER_API_URL}/api/indicators/import'

        for chunk in batched(indicators, 500):
            payload = {'Indicators': []}

            for indicator in chunk:
                indicator_type, indicator_value = extract_indicator_data(indicator.get('pattern'))
                severity = get_severity(indicator.get('confidence'))
                description = get_description(indicator.get('external_references'))
                indicator_type = {'ipv4-addr': 'IpAddress', 'domain-name': 'DomainName', 'url': 'Url'}.get(indicator_type)

                payload['Indicators'].append(
                    {
                        'indicatorValue': indicator_value,
                        'title': 'IoC from ANY.RUN TI Feeds',
                        'description': description,
                        'action': 'Audit',
                        'generateAlert': 'True',
                        'severity': severity,
                        'indicatorType': indicator_type
                    }
                )

            response = self._make_request('POST', url, data=json.dumps(payload))

            if response.status_code >= 300:
                self._throw_error('Failed to load indicators to the Microsoft Defender', response)

    def _make_request(
            self,
            method: str,
            url: str,
            data: dict | str | None = None
        ) -> requests.Response:
        """
        Executes a request ti the specified API endpoint

        :param method: HTTP Request method
        :param url: Endpoint URL
        :param data: Request body
        :return: Response object
        """
        try:
            response = requests.request(method, url, headers=self._headers, data=data)
        except (requests.RequestException, OSError) as error:
            self._throw_error(f'Unspecified Network exception: {traceback.format_exc(error)}. Status code {response.status_code}')
        return response

    def _throw_error(self, error_message: str, response: requests.Response | None = None) -> None:
        """
        Logs error text then builds and raises exception

        :param error_message: Error text
        :param response: Response object
        """
        self._log.error(error_message)

        if response is not None:
            raise RunTimeException(error_message + response.text, response.status_code)
        raise RunTimeException(error_message)
