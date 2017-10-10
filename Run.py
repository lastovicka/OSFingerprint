#!/usr/bin/python3.6

import os
import sys
from datetime import datetime, timedelta
from time import sleep
import Flowmon_ssh
import login
from OS_parser import make_sessions_every_5_min
import getpass
from subprocess import call


tmp_path = 'tmp/'

def round_time(time):
    t_min = time.minute % 5
    t_sec = time.second
    t_mic = time.microsecond
    time = time - timedelta(minutes=t_min, seconds=t_sec, microseconds=t_mic)
    return time


def get_flows(time, pw):
    date_path = time.strftime('%Y/%m/%d/')
    file_path = 'nfcapd.' + time.strftime('%Y%m%d%H%M') + ' '
    if not os.path.isdir(date_path):
        path = ''
        for sub_dir in date_path.split('/'):
            path += sub_dir + '/'
            if not os.path.isdir(path):
                os.mkdir(path, 0o755);
    return Flowmon_ssh.ssh_download(date_path=date_path, file_path=file_path, password=pw)


# TODO real commit
def commit_to_DB(paths):
    for path in paths:
        print(f'Uploading into DB ...{path}')
        sleep(0.5)
    print('Success!')


def clean_tmp_directory(time):
    actual_time = time.strftime('%Y%m%d%H%M')
    prev_time = (time - timedelta(minutes=5)).strftime('%Y%m%d%H%M')

    esc_tmp_path = tmp_path.replace('/', '\/')
    remove_old_files = f"ls -1 {tmp_path} " \
                       f"| grep -v '{actual_time}\\|{prev_time}' " \
                       f"| grep -E '^([0-9]{{12}}_[a-z]{{3,4}}\\.csv)|([0-9]{{12}}\.csv~?)$' " \
                       f"| sed  -e 's/^/{esc_tmp_path}/' " \
                       f"| xargs rm "
    print(f'Cleaning ... {remove_old_files}')
    os.system(remove_old_files)


def run(pw = None):
    time = datetime.strptime('2017-09-25 02:05:00', '%Y-%m-%d %H:%M:%S')
    while True:
        # now = datetime.now() - timedelta(minutes=5)
        # time = round_time(now)
        print(f'Actual time: \t{time}')

        if not os.path.isdir(tmp_path):
            os.mkdir(tmp_path, 0o755);
        file_path = get_flows(time, pw)
        actual_path = make_sessions_every_5_min(file_path, time)
        commit_to_DB(actual_path)
        clean_tmp_directory(time)
        time = time + timedelta(minutes=5)


if __name__ == '__main__':
    print(f'Argument List: \t{str(sys.argv)}')
    if '-p' in sys.argv:
        print('Enter your private key password:')
        pw = getpass.getpass()
    else:
        pw = login.pw
    run(pw)
