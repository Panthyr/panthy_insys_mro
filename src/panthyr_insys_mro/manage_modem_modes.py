#! /usr/bin/python3
# -*- coding: utf-8 -*-
# vim: ts=4:sw=4:expandtab:cuc:autoindent:ignorecase:colorcolumn=99

__author__ = 'Dieter Vansteenwegen'
__email__ = 'dieter.vansteenwegen@vliz.be'
__project__ = 'Panthyr'
__project_link__ = 'https://waterhypernet.org/equipment/'

import argparse
import datetime
import logging
import sys
import time
import requests

from panthyr_insys_mro.insys_mro import InsysMRO
from src.panthyr_insys_mro.insys_mro import MROError

LOG_FMT = '|%(asctime)s|%(levelname)-7.7s|%(module)-15.15s|%(lineno)-0.4d|%(funcName)-15.15s|%(message)s|'
TIME_FMT = '%Y-%m-%d %H:%M:%S.%f'


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
    parser.add_argument(
        'maximum_minutes_offline',
        help='Maximum number of minutes being offline before moving to next modem mode',
        type=int,
        default=10,
    )
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


def goto_next_modem_mode(mro: InsysMRO, current_modem_mode: str) -> str:
    # valid modes: ['normal', 'att', 'verizon']

    if current_modem_mode == 'normal':
        next_modem_mode = 'att'
    elif current_modem_mode == 'att':
        next_modem_mode = 'verizon'
    else:
        next_modem_mode = 'normal'

    mro.set_modem_mode(next_modem_mode)
    return next_modem_mode


def main():
    args = _get_arguments()
    log = _init_logging()
    max_minutes_offline = args.maximum_minutes_offline
    offline_minutes = 0

    while True:
        try:
            mro = InsysMRO(username=args.username, password=args.password, ip=args.ip)
        except requests.exceptions.ConnectionError:
            log.error(f'Could not connect to MRO at IP {args.ip}')
            time.sleep(10)
            continue

        try:
            cell_info = mro.get_cellular_info()
            # curr_profile = mro.current_profile()
            curr_modem_mode = mro.current_modem_mode()
            connection_state = cell_info.get('state', 'Not in returned dict')
        except MROError:
            time.sleep(10)
            continue

        if connection_state != 'Online':
            log.warning(
                f'OFFLINE. Cellular state: [{cell_info}], with mode [{curr_modem_mode}], '
                f'minutes offline: {offline_minutes}', )
            if offline_minutes >= max_minutes_offline:
                offline_minutes = 0
                try:
                    new_profile = goto_next_modem_mode(mro, curr_modem_mode)
                    log.info(f'Changed to profile {new_profile}')
                except KeyError:
                    log.info('Changing modes not supported.')
            offline_minutes += 2
        else:
            offline_minutes = 0
            log.info(
                f'ONLINE. Cellular state: [{cell_info}], using modem mode [{curr_modem_mode}]', )
        mro.logout()
        dt = datetime.datetime.now(datetime.timezone.utc).strftime(TIME_FMT)
        with open('log.csv', 'a') as outp:
            outp.write(f'{dt};{connection_state};{curr_modem_mode};{cell_info}')
        time.sleep(120)


if __name__ == '__main__':
    main()
