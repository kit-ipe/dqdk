import sys
import random

MAX_VAL = 0xFFFFFF
CHANNELS = 168
MASK = 6
TILES = 9

PACKETSZ = 3392
EVENTSZ = 16

def generate_event(maxval):
    energy = random.randint(0, maxval)
    channel = random.randint(0, (TILES * CHANNELS) - 1)
    mask = random.randint(0, MASK - 1)
    return '{' + f'0, {channel}, {energy}, {mask}, 0, 0' + '}'

def nbins_generate(maxval) -> str:
    arrsz = PACKETSZ // EVENTSZ
    events = [generate_event(maxval) for _ in range(arrsz)]
    file_header = """
#ifndef TRISTAN_DUMMY_H
#define TRISTAN_DUMMY_H

#include "ctypes.h"

#ifdef MEMCPY_TEST
struct energy_evt {
    u16 id;
    u16 channel;
    u32 energy : 24;
    u8 mask;
    u16 trigger_info;
    u64 timestamp : 48;
} __attribute__((packed));
typedef struct energy_evt tristan_energy_evt_t;
#else
#include "tristan.h"
#endif\n
    """
    return file_header + f'tristan_energy_evt_t evnts[{arrsz}] = ' + '{\n' + ',\n'.join(events) + '\n};\n#endif'

if __name__ == '__main__':
    pattern = sys.argv[1]
    bin_count = int(sys.argv[2])

    match pattern:
        case '1bin':
            print(nbins_generate(MAX_VAL // bin_count))
        case 'nbins':
            print(nbins_generate(MAX_VAL))
        case _:
            print('Invalid pattern')
