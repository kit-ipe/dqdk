#!/usr/bin/python3
from enum import Enum
import socket
import sys
import time
import subprocess


class DQDKStatus(Enum):
    NONE = "NONE"
    STARTED = "STARTED"
    READY = "READY"
    CLOSED = "CLOSED"


class DQDKCmd(Enum):
    CLOSE = "CLOSE"
    QUERY = "QUERY"


def connect_to_dqdk(host, port=8000):
    sock = socket.socket(
        socket.AF_INET, socket.SOCK_STREAM | socket.SOCK_CLOEXEC)
    sock.connect((host, port))
    try:
        return sock
    except socket.error as e:
        return None


def start_dqdk_process(ifname, tristan_mode, port_range):
    command = ["sudo", "tristan-daq.sh", ifname, tristan_mode, port_range]
    process = subprocess.Popen(command, stdout=open(
        'dqdk.out', 'w'), stderr=open('dqdk.err', 'w'), stdin=subprocess.DEVNULL,)
    time.sleep(3)
    return process.pid


def start_daq(host, ifname, tristan_mode, port_range):
    if start_dqdk_process(ifname, tristan_mode, port_range):
        return connect_to_dqdk(host)
    return None


def get_status(conn: socket.socket):
    try:
        conn.send(DQDKCmd.QUERY.value.encode())
        data = conn.recv(1024).decode()
        return DQDKStatus(data)
    except Exception as e:
        return False


def stop_daq(conn):
    try:
        conn.send(DQDKCmd.CLOSE.value.encode())
        data = conn.recv(1024).decode()
        if DQDKStatus(data) == DQDKStatus.CLOSED:
            return True
    except Exception as e:
        return False
    finally:
        conn.close()


if __name__ == '__main__':
    host = sys.argv[1]
    daq_conn = start_daq(host, 'ens106np0', 'waveform', '5001-5010')
    if daq_conn:
        i = 0
        while i < 2:
            status = get_status(daq_conn)
            print(i, 'Get Status', status)
            time.sleep(1)
            i += 1

        if stop_daq(daq_conn):
            print("Closed")
        else:
            print("Not Closed")
