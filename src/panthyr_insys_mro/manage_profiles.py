#! /usr/bin/python3
# -*- coding: utf-8 -*-
# vim: ts=4:sw=4:expandtab:cuc:autoindent:ignorecase:colorcolumn=99

__author__ = 'Dieter Vansteenwegen'
__email__ = 'dieter.vansteenwegen@vliz.be'
__project__ = 'Panthyr'
__project_link__ = 'https://waterhypernet.org/equipment/'

import argparse
import logging
import sys
import time

from insys_mro import InsysMRO

LOG_FMT = '|%(asctime)s|%(levelname)-7.7s|%(module)-15.15s|%(lineno)-0.4d|%(funcName)s|%(message)s|'

# class ConnectionKeeper:

#     def __init__(self, username: str, password: str, ip: str = '192.168.100.100'):
#         self._username = username
#         self._password = password
#         self._ip = ip

#     def connect(self):
#         self._mro = InsysMRO(
#             username=self._username,
#             password=self._password,
#             ip=self._ip,
#         )


def _get_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        'ip',
        type=str,
        help='IP of the server',
    )
    parser.add_argument(
        'username',
        type=str,
        help='Username to use for logging in.',
    )
    parser.add_argument('password', type=str, help='Password to log in.')
    parser.add_argument('maximum_minutes_offline', type=int, default=10)
    return parser.parse_args()


def _init_logging() -> logging.Logger:

    logging.basicConfig(
        level=logging.INFO,
        format=LOG_FMT,
        handlers=[
            logging.FileHandler(filename='mro_log.log'),
            logging.StreamHandler(sys.stdout),
        ],
    )
    log = logging.getLogger(__name__)
    log.info('-' * 10 + 'Started running' + '-' * 10)
    return log


def goto_next_profile(mro: InsysMRO) -> str:
    all_profiles = mro.get_profiles()
    profilenames = [profile['name'] for profile in all_profiles]
    curr_index = profilenames.index(mro.current_profile())
    next_index = curr_index + 1 if curr_index < len(profilenames) - 1 else 0
    next_profile: str = profilenames[next_index]

    mro.activate_profile(next_profile)
    return next_profile


if __name__ == '__main__':
    args = _get_arguments()
    mro = InsysMRO(username=args.username, password=args.password, ip=args.ip)
    max_minutes_offline = args.maximum_minutes_offline
    offline_minutes = 0
    log = _init_logging()

    while True:
        cell_info = mro.get_cellular_info()
        curr_profile = mro.current_profile()
        log.info(f'Profile: {curr_profile}, Cellular: {cell_info}')

        if cell_info['state'] != 'Online':
            log.warning(
                f'Cellular is {cell_info["state"]} with profile {curr_profile}, '
                f'minutes offline: {offline_minutes}',
            )
            offline_minutes += 2
            if offline_minutes >= max_minutes_offline:
                offline_minutes = 0
                new_profile = goto_next_profile(mro)
                log.info(f'Changed to profile {new_profile}')
        else:
            offline_minutes = 0
        time.sleep(120)
