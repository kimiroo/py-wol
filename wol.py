import sys
import socket
import struct
import re

APP_NAME = 'py_WOL'
APP_VER = '0.1 BETA'
APP_AUTHOR = 'kimiroo'
APP_URL = 'https://github.com/kimiroo/py_wol'
APP_DESC = 'Broadcasts WOL magic packets to target client within python script or by standalone.'
APP_LICENSE_TYPE = 'MIT'
APP_LICENSE = '''Copyright 2024 kimiroo

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.'''

def get_ip_addr():
    ip = None
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.connect(("1.1.1.1", 443))
        sock.settimeout(None)

        ip = sock.getsockname()[0]

    ## Fallback to alt. method if machine is not connected to internet
    except:
        ip = socket.gethostbyname(socket.gethostname())

    return ip

def is_correct_mac(mac_addr):
    pattern = r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$'
    
    return bool(re.match(pattern, mac_addr))

def is_correct_ip(ip_addr):
    pattern = r'^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}$'
    
    return bool(re.match(pattern, ip_addr))

def wol(mac_addr: str, ip_addr: str=None):

    if not(is_correct_mac(mac_addr)):
        raise(ValueError(f'Invalid MAC Address format: \'{mac_addr}\''))
    
    mac_split = re.split(r'-|:', mac_addr)

    ## Get current ip addr if not given
    ip = get_ip_addr() if (ip_addr == None) else ip_addr
    
    if not(is_correct_ip(ip)):
        raise(ValueError(f'Invalid IPv4 Address format: \'{ip}\''))

    ## Build subnet for target network
    ip_split = ip.split(".")
    target_mask = f'{ip_split[0]}.{ip_split[1]}.{ip_split[2]}.255'

    ## Build magic packet
    addr = struct.pack("BBBBBB",
                        int(mac_split[0], 16),
                        int(mac_split[1], 16),
                        int(mac_split[2], 16),
                        int(mac_split[3], 16),
                        int(mac_split[4], 16),
                        int(mac_split[5], 16))

    magic = b"\xFF" * 6 + addr * 16
    
    print(f'Target MAC Addr.: {mac_split[0]}-{mac_split[1]}-{mac_split[2]}-{mac_split[3]}-{mac_split[4]}-{mac_split[5]}')
    print(f'Current IP Addr.: {ip}')
    print(f'IP Addr. Given:   {True if (ip_addr != None) else False}')
    print(f'Target IP Mask:   {target_mask}\n')

    ## Send magic packet
    is_broadcast_successful = False
    
    try:
        print('Broadcasting magic packet... ', end='')
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.sendto(magic,(target_mask, 9))
        sock.close()
    except Exception as e:
        print('Failed')
        print(f'  Reason: {e}')
    else:
        print('Successful')
        is_broadcast_successful = True
        
    return is_broadcast_successful
    
def _display_version():
    print(f'{APP_NAME} ({APP_VER})\n')

def _display_help():
    _display_version()
    print(APP_DESC+'\n')
    print('''Usage: wol.py [options...]
  -m, --mac <mac_address>   [Required] Provides Target client's MAC address
  -i, --ip <ipv4_address>   [Optional] Provides target interface's ip address (IPv4 only)
  -V, --version             Shows version number and quit
  -h, --help                Shows this help message and quit''')


## Standalone wrapper
if (__name__ == '__main__'):
    ip = None
    mac = None
    
    if (len(sys.argv) < 2):
        print('Too few arguments given. Try \'wol.py --help\' for more information.')
        exit()
    
    if (sys.argv[1] == '-m' or sys.argv[1] == '--mac' or sys.argv[1] == '-i' or sys.argv[1] == '--ip'):
        pass
    elif (sys.argv[1] == '-h' or sys.argv[1] == '--help'):
        _display_help()
        exit()
    elif (sys.argv[1] == '-V' or sys.argv[1] == '--version'):
        _display_version()
        exit()
    else:
        print(f'\'{sys.argv[1]}\' is not a valid argument. Try \'wol.py --help\' for more information.')
        exit()
        
    for idx, i in enumerate(sys.argv[1:]):
        if (i == '-m' or i == '--mac'):
            mac = sys.argv[idx+2]
        elif (i == '-i' or i == '--ip'):
            ip = sys.argv[idx+2]
    
    _display_version()
    print('Launched in standalone mode\n')
    wol(mac_addr=mac, ip_addr=ip)
    exit()
else:
    wol('00-11-22-33-44-55')