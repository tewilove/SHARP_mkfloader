#!/usr/bin/python

import struct
import usb.core
from usb.core import USBError as USBError
import usb.util
import argparse

FLOADER_VID = 0x04dd
FLOADER_PID = 0x933a
FLOADER_INTF = 1
FLOADER_ALT = 1

FLOADER_CMD_BOOT = 0x00
FLOADER_CMD_READ_NAME = 0x30

parser = argparse.ArgumentParser()
parser.add_argument('--read', type=str, dest='ATTR', choices=['name'])
parser.add_argument('--boot', type=str, dest='LOADER')
ARGS = parser.parse_args()

class FloderError(Exception):
    pass

def floader_send(intf, data):
    intf[1].write(data)

def floader_recv(intf, size):
    return intf[0].read(size)

def floader_send_small(intf, cmd, data):
    size = 1
    if data is not None:
        size += len(data)
    if size > 255:
        raise FloderError('floader: invalid request')
    chk = 0
    chk += cmd
    chk &= 0xff
    chk += size
    chk &= 0xff
    if data is not None:
        for val in data:
            chk += val
            chk &= 0xff
    chk = ~chk
    chk &= 0xff
    floader_send(intf, struct.pack('>B', cmd))
    floader_send(intf, struct.pack('>B', size))
    if data is not None:
        floader_send(intf, data)
    floader_send(intf, struct.pack('>B', chk))

def floader_send_large(intf, cmd, data):
    size = 1
    if data is not None:
        size += len(data)
    chk = 0
    for i in range(0, 4):
        chk += ((size >> (i * 8)) & 0xff)
        chk &= 0xff
    if data is not None:
        for val in data:
            chk += val
            chk &= 0xff
    chk = ~chk
    chk &= 0xff
    floader_send(intf, struct.pack('>B', cmd))
    floader_send(intf, struct.pack('>I', size))
    if data is not None:
        floader_send(intf, data)
    floader_send(intf, struct.pack('>B', chk))

def floader_recv_data(intf, size):
    data = floader_recv(intf, size)
    code = data[0]
    size = data[1]
    return code, data[2:size + 1]

def floader_recv_status(intf):
    return floader_recv_data(intf, 4)

# Read device name, not supported by old devices
def floader_read_name(intf):
    floader_send_small(intf, FLOADER_CMD_READ_NAME, None)
    code, data = floader_recv_data(intf, 11)
    if code == FLOADER_CMD_READ_NAME + 1:
        return ''.join([chr(x) for x in data])
    dump = ''.join(['{:02X}'.format(x) for x in data])
    message = 'floader: invalid response: {0}: {1}'.format(code, dump)
    raise FloderError(message)

# Send loader and read response
def floader_boot(intf, path):
    with open(path, 'rb') as f:
        content = f.read()
    # Send "security record"
    data = b'\xF9\x22\x5D\x50\xE9\xD2\x44\x60\x11\x92\xA0\x3B\x51\x1F\x80\xC1'
    floader_send(intf, data)
    # Send boot command, 0xff => alternative address, otherwise normal address
    floader_send_large(intf, FLOADER_CMD_BOOT, b'\x00' + content)
    code, data = floader_recv_status(intf)
    if code == FLOADER_CMD_BOOT + 1:
        return data[0]
    dump = ''.join(['{:02X}'.format(x) for x in data])
    message = 'floader: invalid response: {0}: {1}'.format(code, dump)
    raise FloderError(message)

def main():
    dev = usb.core.find(idVendor = FLOADER_VID, idProduct = FLOADER_PID)
    if dev is None:
        raise FloderError('floader: no device')
    dev.set_interface_altsetting(FLOADER_INTF, FLOADER_ALT)
    cfg = dev.get_active_configuration()
    intf = cfg[(FLOADER_INTF, FLOADER_ALT)]
    if ARGS.ATTR != None:
        if ARGS.ATTR == 'name':
            print(floader_read_name(intf))
    if ARGS.LOADER != None:
        print(floader_boot(intf, ARGS.LOADER))

if __name__ == '__main__':
    main()
