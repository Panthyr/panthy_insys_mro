#! /usr/bin/python3
# -*- coding: utf-8 -*-
# vim: ts=4:sw=4:expandtab:cuc:autoindent:ignorecase:colorcolumn=99

__author__ = 'Dieter Vansteenwegen'
__email__ = 'dieter.vansteenwegen@vliz.be'
__project__ = 'Panthyr'
__project_link__ = 'https://waterhypernet.org/equipment/'

import requests
import logging
from typing import Dict

log = logging.getLogger(__name__)


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
        login_url = f'{self.url_base}/auth/login'
        login_data = {'username': username, 'password': password}
        auth_result = requests.post(login_url, json=login_data)
        access_token = auth_result.json()['access']
        self.header_auth = {'Authorization': f'Bearer {access_token}'}

    # def check_status(self):
    #     status_overview_url = f'{self.url_base}/status/overview'
    #     status_overview = requests.get(status_overview_url, headers=self.header_auth)

    def _get(self, url: str) -> Dict:
        target_url = f'{self.url_base}{url}'
        return requests.get(target_url, headers=self.header_auth).json()

    def _device_info(self) -> Dict:
        device_info_url = f'{self.url_base}/status/device_info'
        device_info = requests.get(device_info_url, headers=self.header_auth)
        return device_info.json()

    def get_firmware_version(self):
        return self._device_info()['status']['list'][0]['firmware_version']

    def get_cellular_info(self) -> Dict:
        cellular_info_raw = self._get(url='/status/lte_serial2')['status']['unique']

        return cellular_info_raw

    # def get_cellular_info(self) -> Dict:
