#!/usr/bin/env python3

import argparse
import os
import io
import ipaddress
import json
import hmac
import logging
import sys
import struct
import time
import uuid

import socket
import ssl

logger = logging.getLogger('d4-pyclient')

#### BASIC FUNCTIONS ####

def generate_uuid(filename):
    sensor_uuid = str(uuid.uuid4())
    with open(filename, 'w') as f:
        f.write(sensor_uuid)
    return sensor_uuid

def get_config_from_file(config_dir, filename, r_type='str'):
    filename = os.path.join(config_dir, filename)
    if not os.path.isfile(filename):
        logger.error('config file not found: {}'.format(filename))
        sys.exit(1)

    with open(filename, 'r') as f:
        config = f.read()
    while config[-1] == '\n':
        config = config[:-1]

    if r_type == 'int':
        try:
            config = int(config)
        except:
            logger.error('config file: {}, invalid type'.format(filename))
            sys.exit(1)
    else:
        config = config.encode()
    return config

##-- BASIC FUNCTIONS --##


class D4Client(object):
    """D4Client."""

    def __init__(self, config_dir, check_certificate):
        if not os.path.isdir(config_dir):
            logger.error('This config directory is invalid: {},'.format(config_dir))
            sys.exit(1)

        # HMAC Key, Pre-shared-Key
        self.key = get_config_from_file(config_dir, 'key', r_type='str')
        # D4 packet type
        self.type = get_config_from_file(config_dir, 'type', r_type='int')
        if self.type < 0 and self.type > 255:
            logger.error('unsuported d4 type: {}'.format(self.type))
            sys.exit(1)
        # protocol version
        self.version = get_config_from_file(config_dir, 'version', r_type='int')
        if self.version < 0:
            logger.error('invalid version: {}'.format(self.version))
            sys.exit(1)
        # snaplen, default is 4096
        self.snaplen = get_config_from_file(config_dir, 'snaplen', r_type='int')
        if self.snaplen <= 0:
            logger.error('invalid snaplen')
            sys.exit(1)
        # Sensor UUID
        self.get_sensor_uuid(config_dir)

        # data source
        self.set_source(config_dir)

        # destination
        self.check_certificate = check_certificate
        self.get_destination(config_dir)

        # get metaheader
        self.set_metaheader_json(config_dir)

        self.reconnect = True
        self.connect()

    # # TODO: check if valid uuid
    def get_sensor_uuid(self, config_dir):
        filename = os.path.join(config_dir, 'uuid')
        if not os.path.isfile(filename):
            sensor_uuid = generate_uuid(filename)
        else:
            with open(filename, 'r') as f:
                sensor_uuid = f.read()
            if sensor_uuid[-1] == '\n':
                sensor_uuid = sensor_uuid[:-1]
        self.uuid = sensor_uuid.replace('-', '')

    def set_source(self, config_dir):
        filename = os.path.join(config_dir, 'source')
        if not os.path.isfile(filename):
            logger.error('source file not found: {}'.format(filename))
            sys.exit(1)

        with open(filename, 'r') as f:
            source = f.read().replace('\n', '')

        if source == 'stdin':
            self.source = 'stdin'
        elif source == 'redis' or source == 'd4server':
            self.source = 'redis'
            r_conf = get_config_from_file(config_dir, source, r_type='str')
            redis_db = int(r_conf.split('/')[-1]) # # TODO: Error message
            redis_port = int(r_conf.split(':')[-1]) # # TODO: Error message
            redis_host = r_conf.split(':')[0] # # TODO: Error message
            try:
                self.redis_src = redis.StrictRedis( host=redis_host, port=redis_port, db=redis_db)
            except Exception as e:
                print(e)
                logger.error(f'Redis Error: {redis_host}:{redis_port}/{redis_db}')
                sys.exit(1)

    def get_destination(self, config_dir):
        filename = os.path.join(config_dir, 'destination')
        if not os.path.isfile(filename):
            logger.error('destination file not found: {}'.format(filename))
            sys.exit(1)

        with open(filename, 'r') as f:
            destination = f.read().replace('\n', '')

        if destination == 'stdout':
            self.destination = 'stdout'
        # Get server address
        else:
            self.destination = 'd4server'

            if not ':' in destination:
                # port = 80 ?
                logger.error('The destination is invalid')
                sys.exit(1)
            self.host, port = destination.rsplit(':', 1)
            # verify port
            try:
                self.port = int(port)
            except:
                logger.error('Invalid port')
                sys.exit(1)

    def connect(self):
        if self.destination == 'd4server':
            while True:

                # verify address
                try:
                    host = str(ipaddress.ip_address(self.host))
                except ValueError:
                    # get IP host
                    # host = socket.gethostbyname(host)
                    try:
                        host = socket.gethostbyname(self.host)
                    except:
                        logger.error('Destination Host: Name or service not known')
                        sys.exit(1)

                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                # TCP Keepalive
                s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                s.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 1)
                s.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 15)
                s.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 15)

                # SSL
                if self.check_certificate:
                    cert_reqs_option = ssl.CERT_REQUIRED
                else:
                    cert_reqs_option = ssl.CERT_NONE
                self.client_socket = ssl.wrap_socket(s, cert_reqs=cert_reqs_option, ca_certs=None, ssl_version=ssl.PROTOCOL_TLS)
                # TCP connect
                try:
                    self.client_socket.connect((host, self.port))
                except ConnectionRefusedError:
                    logger.error('Connection to {}:{} refused'.format(host, self.port))
                    if self.reconnect:
                        time.sleep(10)
                        continue
                    else:
                        sys.exit(1)
                except socket.timeout:
                    logger.error('Connection to {}:{} timeout'.format(host, self.port))
                    if self.reconnect:
                        time.sleep(10)
                        continue
                except ssl.SSLError as e:
                    logger.error(e)
                    sys.exit(1)
                break

        # send metaheader
        if self.type == 2 or self.type == 254:
            self.send_metaheader()


    #### METAHEADER ####

    def set_metaheader_json(self, config_dir):
        if self.type == 2 or self.type == 254:
            filename = os.path.join(config_dir, 'metaheader.json')
            if not os.path.isfile(filename):
                logger.error('Metaheader file not found: {}'.format(filename))
                sys.exit(1)

            with open(filename, 'rb') as f:
                metaheader = f.read()
            try:
                metaheader = json.loads(metaheader)
            except:
                logger.error('The JSON file is invalid')
                sys.exit(1)
            self.metaheader = json.dumps(metaheader).encode()
        else:
            self.metaheader = None

    def send_metaheader(self):
        self.type = 2
        # self.set_metaheader_json(config_dir) ####################### reload meta ????
        # send D4 metaheader
        buffer = self.metaheader
        buffer = self.prepare_and_send_data(buffer, send_all=True)
        # change type
        self.type = 254

    ##-- METAHEADER --##

    #### D4 PACKETS ####

    def create_hmac(self, data):
        data_hmac = hmac.new(self.key, msg=data, digestmod='sha256')
        return data_hmac.digest()

    # Create D4 header
    def create_d4_header(self, data):
        # Get header fieldscat
        h_version_type = struct.pack('BB', self.version, self.type)
        h_timestamp = struct.pack('Q', int(time.time()))
        h_size = struct.pack('I', len(data))
        h_uuid = bytearray.fromhex(self.uuid)

        # Get Hmac field
        # The HMAC is computed on the header with a HMAC value set to 0
        d4_header = h_version_type + h_uuid + h_timestamp + bytearray(32) + h_size
        d4_data = d4_header + data
        h_hmac = self.create_hmac(d4_data)

        d4_header = h_version_type + h_uuid + h_timestamp + h_hmac + h_size
        return d4_header

    def prepare_and_send_data(self, buffer, send_all=False):
        # Pack data
        while len(buffer) > self.snaplen:
            data_to_pack = buffer[0:self.snaplen]
            buffer = buffer[self.snaplen:]

            # Pack data
            d4_header = self.create_d4_header(data_to_pack)
            d4_packet = d4_header + data_to_pack

            # Send data
            self.send_d4_packet(d4_packet)
        if send_all and buffer:
            # Pack data
            d4_header = self.create_d4_header(buffer)
            d4_packet = d4_header + buffer

            # Send data
            self.send_d4_packet(d4_packet)
            buffer = b''
        return buffer

    # Send (D4 header + data) to D4Server
    def send_d4_packet(self, d4_packet):
        if self.destination == 'stdout':
            sys.stdout.buffer.write(d4_packet)
            sys.stdout.flush()
        else:
            # # TODO: logs errors
            try:
                self.client_socket.send(d4_packet)
            except Exception as e:
                if self.reconnect:
                    time.sleep(10)
                    self.connect()
                    self.send_d4_packet(d4_packet)

    ##-- D4 PACKETS --##

    def send_data(self):
        if self.source == 'stdin':
            buffer = b''
            try:
                for data in io.open(sys.stdin.fileno(), mode='rb', buffering=0):
                    if data:
                        buffer = buffer + data
                        buffer = self.prepare_and_send_data(buffer)

                self.prepare_and_send_data(buffer, send_all=True)
                if not isinstance(self.client_socket, str):
                    self.client_socket.shutdown(socket.SHUT_RDWR)

            # Send buffer content
            except KeyboardInterrupt:
                # Pack data
                self.prepare_and_send_data(buffer, send_all=True)
                if not isinstance(destination, str):
                    self.client_socket.shutdown(socket.SHUT_RDWR)
        else:
            # # TODO: redis list
            pass

    def send_manual_data(self, data, add_new_line=False):
        if len(data) > 1:
            # Encode data
            if type(data) is not bytes:
                data = data.encode()
            # Add new line
            if self.type == 3 or self.type == 8:
                if data[-1:] != b'\n':
                    data = data + b'\n'
            self.prepare_and_send_data(data, send_all=True)

 # # TODO: close/shutdown client

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--config' ,help='config directory' ,type=str, dest='config', required=True)
    parser.add_argument('-cc', '--check_certificate' ,help='check server certificate', action="store_true")
    args = parser.parse_args()
    config_dir = args.config
    check_certificate = args.check_certificate

    d4_client = D4Client(config_dir, check_certificate)
    while True:
        d4_client.send_manual_data(b'data test 1235\n')
        time.sleep(1)
    #d4_client.send_data()
