#! /usr/bin/python3
# -*- coding: utf-8 -*-
# vim: ts=4:sw=4:expandtab:cuc:autoindent:ignorecase:colorcolumn=99

__author__ = 'Dieter Vansteenwegen'
__email__ = 'dieter.vansteenwegen@vliz.be'
__project__ = 'Panthyr'
__project_link__ = 'https://waterhypernet.org/equipment/'

import requests
import logging
from typing import Dict, Union

log = logging.getLogger(__name__)


class IncorrectCredentialsError(Exception):
    pass


class InsysMRO():

    def __init__(  #nosec B107
        self,
        username: str = 'status',
        password: str = 'status',
        ip: str = '192.168.100.100',
    ):
        self.url_base = f'http://{ip}:80/api/v2_0'
        self._login(username=username, password=password)

    def _login(self, username: str, password: str) -> None:
        # sourcery skip: raise-from-previous-error
        login_url = f'{self.url_base}/auth/login'
        login_data = {'username': username, 'password': password}
        auth_result = requests.post(login_url, json=login_data)
        if auth_result.status_code == 401:
            raise IncorrectCredentialsError
        access_token = auth_result.json()['access']
        self.header_auth = {'Authorization': f'Bearer {access_token}'}

    def _get_from_url(self, url: str) -> Dict:
        target_url = f'{self.url_base}{url}'
        return requests.get(target_url, headers=self.header_auth).json()

    def _post_to_url(self, url: str, json: Union[dict, None] = None) -> requests.Response:
        target_url = f'{self.url_base}{url}'
        return requests.post(target_url, json=json, headers=self.header_auth)

    def _manual_action(self, type: str, options: Union[dict, None] = None) -> requests.Response:
        if options is None:
            options = {}
        json = {
            'method': 'manual_action',
            'params': {
                'type': type,
                'options': options,
            },
        }
        return self._post_to_url(url='/operation', json=json)

    def force_ntp_sync(self) -> bool:
        rtn = self._manual_action(type='ntp_sync', options={})
        return rtn.status_code == 201

    def _device_info(self) -> Dict:
        device_info_url = f'{self.url_base}/status/device_info'
        device_info = requests.get(device_info_url, headers=self.header_auth)
        return device_info.json()

    def reboot_device(self) -> bool:
        rtn = self._post_to_url(url='/reboot')
        return rtn.status_code == 201

    def get_firmware_version(self):
        return self._device_info()['status']['list'][0]['firmware_version']

    def get_cellular_info(self) -> Dict:
        field_mapping = [
            ['state', 'state'],
            ['provider', 'provider'],
            ['provider_name', 'provider_name'],
            ['used_net', 'connection'],
            ['cell_id', 'cell_id'],
            ['signal', 'signal_strength'],
            ['RSSI', 'RSSI'],
            ['sim_state', 'sim_state'],
            ['pin_state', 'pin_state'],
            ['pin_retries', 'pin_retries'],
            ['IMEI', 'IMEI'],
            ['temperature', 'temperature'],
            ['input_voltage_1', 'input_voltage'],
        ]
        cellular_info_raw = self._get_from_url(url='/status/lte_serial2')['status']['unique']
        return {field[1]: cellular_info_raw[field[0]] for field in field_mapping}
