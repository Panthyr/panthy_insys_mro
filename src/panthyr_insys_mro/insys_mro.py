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
import tenacity

LOG_FMT = '|%(asctime)s|%(levelname)-7.7s|%(module)-15.15s|%(lineno)-0.4d|%(funcName)-10.10s|%(message)s|'
log = logging.getLogger(__name__)


class MROError(Exception):
    pass


class IncorrectCredentialsError(MROError):
    """Cannot log in because username/password combination is not correct."""


class NoPermissionError(MROError):
    """The user is authenticated, but has no rights to perform this action/operation."""


class InvalidReplyError(MROError):
    """Got an invalid reply from the device."""


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
        """Log in to the router.

        Login and create the authorisation header

        Args:
            username (str): username for the router
            password (str): password for the router

        Raises:
            IncorrectCredentialsError: The supplied credentials are incorrect.
        """
        # sourcery skip: raise-from-previous-error
        login_url = f'{self.url_base}/auth/login'
        login_data = {'username': username, 'password': password}
        # try:
        auth_result = requests.post(login_url, json=login_data)
        # except requests.exceptions.ConnectionError:

        if auth_result.status_code == 401:
            raise IncorrectCredentialsError
        access_token = auth_result.json()['access']
        self.header_auth = {'Authorization': f'Bearer {access_token}'}

    @tenacity.retry(
        reraise=True,
        stop=tenacity.stop_after_attempt(2),
        after=tenacity.after_log(log, logging.WARNING),
    )
    def _get_from_url(self, url: str) -> Dict:
        """Helper method to perform a GET request.

        Args:
            url (str): partial url to be added to f'http://{ip}:80/api/v2_0'

        Returns:
            Dict: data from device
        """
        # TODO: exception for invalid URL or auth
        target_url = f'{self.url_base}{url}'
        rtn = requests.get(target_url, headers=self.header_auth)
        if rtn.status_code != 200:
            log.warning(f'Received code {rtn.status_code} for request to {url}.')
            raise InvalidReplyError
        return rtn.json()

    @tenacity.retry(
        reraise=True,
        stop=tenacity.stop_after_attempt(2),
        after=tenacity.after_log(log, logging.WARNING),
    )
    def _put_to_url(self, url: str, json: Union[dict, None] = None) -> requests.Response:
        target_url = f'{self.url_base}{url}'
        rtn = requests.put(target_url, json=json, headers=self.header_auth)
        if rtn.status_code != 200:
            log.warning(f'Received code {rtn.status_code} for put to {url}.')
        return rtn

    def _post_to_url(self, url: str, json: Union[dict, None] = None) -> requests.Response:
        """Helper method to perform a POST request.

        Args:
            url (str): partial url to be added to f'http://{ip}:80/api/v2_0'
            json (Union[dict, None], optional): JSON data to post. Defaults to None.

        Returns:
            requests.Response: Response from the request
        """
        # TODO: exception for invalid URL or auth
        target_url = f'{self.url_base}{url}'
        rtn = requests.post(target_url, json=json, headers=self.header_auth)
        if rtn.status_code != 200:
            log.warning(f'Received code {rtn.status_code} for post to {url}.')
        return rtn

    def _manual_action(self, type: str, options: Union[dict, None] = None) -> requests.Response:
        """Helper method to perform a manual action (POST).

        Args:
            type (str): type of action to put in params (ie. 'ntp_sync')
            options (Union[dict, None], optional): Options, if required for the action.
                                                    Defaults to None.

        Returns:
            requests.Response: Response from the POST request.

        Raises:
            NoPermissionError: if the user has no rights to perform the requested action.
        """
        # TODO: exception for operation or auth
        if options is None:
            options = {}
        json = {
            'method': 'manual_action',
            'params': {
                'type': type,
                'options': options,
            },
        }
        rtn = self._post_to_url(url='/operation', json=json)
        if rtn.status_code == 403:
            raise NoPermissionError
        return rtn

    def force_ntp_sync(self) -> bool:
        """Force an NTP sync.

        Force the router to sync its time from an external NTP server.

        Returns:
            bool: True if succesful
        """
        try:
            rtn = self._manual_action(type='ntp_sync', options={})
        except NoPermissionError:
            log.error('User has no permission to force an NTP update.')
            raise
        return rtn.status_code == 201

    def _device_info(self) -> Dict:
        """Helper method to get all device status info.

        Returns:
            Dict: device status info as returned from device
        """
        device_info_url = f'{self.url_base}/status/device_info'
        device_info = requests.get(device_info_url, headers=self.header_auth)
        return device_info.json()

    def get_firmware_version(self) -> str:
        """Get the current firmware version from the device.

        Gets all the device status info, returns the firmware version as a string

        Returns:
            str: Current firmware version
        """
        return self._device_info()['status']['list'][0]['firmware_version']

    def reboot_device(self) -> bool:
        """Force a cold reboot.

        Returns:
            bool: True if succesful, False if not (authorisation, HW error, ...)
        """
        # TODO: set up new connection after reboot
        # TODO: use tenacity to retry login up to x seconds timeout?
        rtn = self._post_to_url(url='/reboot')
        return rtn.status_code == 201

    def get_cellular_info(self) -> Dict:
        """Get cellular info from device.

        Returns a dict with state, provider, provider_name, used_net, cell_id, signal, RSSI,
            sim_state, pin_state, pin_retries, IMEI, temperature and input_voltage_1 items.

        Returns:
            Dict: status info from the cellular module
        """
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
        rtn = {}
        try:
            rtn = {field[1]: cellular_info_raw[field[0]] for field in field_mapping}
        except KeyError as e:
            log.error(f'KeyError: {e}, {cellular_info_raw=}')
            rtn = {}
        return rtn

    def _change_lte2_state(self, state: str) -> bool:
        options = {'name': 'lte2', 'state_change': state}
        response = self._manual_action(type='modem_state', options=options)
        if type(response.status_code) != int:
            raise TypeError(
                'Status code not int: '
                f'{response.status_code}, type: {type(response.status_code)}', )
        return response.status_code == 201

    def power_cycle_lte(self) -> bool:
        """Restart the lte modem.

        Returns:
            bool: True if turn off and back on succeeded.
        """
        # TODO: improved handling/reporting of issues (ie. turn off works but back on not, ...)
        # TODO: needs sleep in between off/on cycle?
        success = False
        turn_off = self._change_lte2_state(state='turn_off')
        return bool(turn_off and self._change_lte2_state(state='turn_on'))

    def get_profiles(self) -> list[dict[str, bool]]:
        """Get a list of the profiles available on the device.

        Returns a list with a dict for each profile.
        Items in the dict: 'name':str, 'last_activated':bool, 'modified':bool

        Example return:
            [{
            'name': 'quick_start_profile_2',
            'last_activated': True,
            'modified': False
            }, {
                'name': 'Running_copy',
                'last_activated': False,
                'modified': False
            }]
        Returns:
            list[dict[str,bool]]: dict for each profile
                                containing 'name', 'last_activated' and 'modified'
        """
        rtn = self._get_from_url('/profiles')
        return rtn['profiles']

    def current_profile(self) -> str:
        all_profiles = self.get_profiles()
        rtn = ''
        for profile in all_profiles:
            if profile['last_activated']:
                rtn = profile['name']
                continue
        return rtn

    def activate_profile(self, profilename: str) -> bool:
        """Activate given profile.

        Args:
            profilename (str): name of the profile to be activated

        Returns:
            bool: True if received status code 200
        """
        success = False
        json = {'profile': profilename}
        try:
            rtn = self._put_to_url(url='/profiles/activate', json=json)
            if rtn.status_code == 200:
                success = True
        except Exception as e:
            log.exception(e)
        return success
