#! /usr/bin/python3
import sys
import os
import math
import csv

MODES = {'listwave': 3392, 'energyhisto': 16}


def log2(x):
    return math.log(x) / math.log(2)


def extract_event(rawevent: bytearray):
    """
    struct energy_evt {
        u16 id;
        u16 channel;
        u32 energy : 24;

        // Auxiliary Information
        u8 trigger_flags; // bits 0 to 7
        u8 hist_class : 3; // bits 8 to 10;
        u8 reserved: 5; // bits 11 to 15
        u8 multiplicity; // bits 16 to 24
        
        u64 timestamp : 48;
    }
    """
    print('Event', rawevent[:16].hex())
    return {
        'id': int.from_bytes(rawevent[0:2]),
        'channel': int.from_bytes(rawevent[2:4]),
        'energy': int.from_bytes(rawevent[4:7]),
        # 'trigger_flags': int.from_bytes(rawevent[7:8]),
        'hist_class': int.from_bytes(rawevent[8:9]) & 0x7,
        # 'multi': int.from_bytes(rawevent[9:10]),
        # 'timestamp': int.from_bytes(rawevent[10:16])
    }

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print('Invalid args')
        sys.exit(1)

    mode = sys.argv[1]
    filename = sys.argv[2]

    if mode not in MODES:
        print('Invalid mode')
        sys.exit(1)

    print('Reading File...')
    with open(filename, 'rb') as file:
        buffer = bytearray(os.fstat(file.fileno()).st_size)
        lng = file.readinto(buffer)

    print('Read', lng, 'bytes')
    total_events = lng / MODES[mode]
    print('Decoding', total_events, 'Events...')
    total_decodedbytes = 0
    with open('events.csv', 'w') as f:
        writer = csv.DictWriter(f, fieldnames=['id', 'channel', 'energy', 'hist_class',])
        writer.writeheader()
        while total_decodedbytes < len(buffer):
            rawevent = buffer[total_decodedbytes:total_decodedbytes + 16]
            event = extract_event(rawevent)
            writer.writerow(event)
            total_decodedbytes += MODES[mode]
