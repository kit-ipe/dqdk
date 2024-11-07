#! /usr/bin/python3

import sys

if __name__ == '__main__':
    with open(sys.argv[1], 'rb') as file:
        while event := file.read(16):
            print(event)
