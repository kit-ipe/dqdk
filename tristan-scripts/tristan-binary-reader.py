#! /usr/bin/python3
import sys
import os
import math

MODES = {'listwave': 18, 'energyhisto': 16}


def log2(x):
    return math.log(x) / math.log(2)


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print('Invalid args')
        sys.exit(1)

    mode = sys.argv[1]
    filename = sys.argv[2]

    if mode not in MODES:
        print('Invalid mode')
        sys.exit(1)

    events = []
    print('Reading File...')
    with open(filename, 'rb') as file:
        buffer = bytearray(os.fstat(file.fileno()).st_size)
        lng = file.readinto(buffer)

    print('Read', lng, 'bytes')
    total_events = lng / MODES[mode]
    print('Decoding', total_events, 'Events...')
    total_decodedbytes = 0
    while total_decodedbytes != len(buffer):
        rawevent = buffer[total_decodedbytes:total_decodedbytes + 16]
        event = {
            'id': int.from_bytes(rawevent[0:2]),
            'channel': int.from_bytes(rawevent[2:4]),
            'energy': int.from_bytes(rawevent[4:7]),
            'histo': log2(int.from_bytes(rawevent[7:8])),
            'trigger_info': int.from_bytes(rawevent[8:10]),
            'timestamp': int.from_bytes(rawevent[10:])
        }
        events.append(event)

        total_decodedbytes += MODES[mode]
