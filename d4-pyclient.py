#!/usr/bin/env python3

import argparse
import os
import io
import ipaddress
import json
import hmac
import sys
import struct
import time
import uuid # use from

import socket
import ssl

from urllib.parse import urlparse

import datetime

import logging

logger = logging.getLogger('d4-pyclient')

def generate_uuid(filename):
    sensor_uuid = str(uuid.uuid4())
    with open(filename, 'w') as f:
        f.write(sensor_uuid)
    return sensor_uuid

def create_hmac(hmac_key, data):
    data_hmac = hmac.new(hmac_key, msg=data, digestmod='sha256')
    return data_hmac.digest()

def create_d4_header(version, type, sensor_uuid, hmac_key, data):
    # Get header fieldscat
    h_version_type = struct.pack('BB', version, type)
    h_timestamp = struct.pack('Q', int(time.time()))
    h_size = struct.pack('I', len(data))
    h_uuid = bytearray.fromhex(sensor_uuid)

    # Get Hmac field
    # The HMAC is computed on the header with a HMAC value set to 0
    d4_header = h_version_type + h_uuid + h_timestamp + bytearray(32) + h_size
    d4_data = d4_header + data
    h_hmac = create_hmac(hmac_key, d4_data)

    d4_header = h_version_type + h_uuid + h_timestamp + h_hmac + h_size
    return d4_header

def prepare_data(version, type, sensor_uuid, hmac_key, snaplen, buffer, destination):
    # Pack data
    while len(buffer) > snaplen:
        data_to_pack = buffer[0:snaplen]
        buffer = buffer[snaplen:]
        # Pack data
        pack_d4_data(version, type, sensor_uuid, hmac_key, data_to_pack, destination)
    return buffer


def pack_d4_data(version, type, sensor_uuid, hmac_key, data, destination):
    # Pack data
    d4_header = create_d4_header(version, type, sensor_uuid, hmac_key, data)
    d4_data = d4_header + data

    # Send data
    send_d4_data(destination, d4_data)

def send_d4_data(destination, d4_data):
    if destination == 'stdout':
        sys.stdout.buffer.write(d4_data)
        sys.stdout.flush()
    else:
        destination.send(d4_data)

def get_config_from_file(filename, r_type='str'):
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

# # TODO: check if valid uuid
def get_sensor_uuid(config_dir):
    filename = os.path.join(config_dir, 'uuid')
    if not os.path.isfile(filename):
        sensor_uuid = generate_uuid(filename)
    else:
        with open(filename, 'r') as f:
            sensor_uuid = f.read()
        if sensor_uuid[-1] == '\n':
            sensor_uuid = sensor_uuid[:-1]
    return sensor_uuid.replace('-', '')

def load_config(config_dir):
    if not os.path.isdir(config_dir):
        logger.error('This config directory is invalid: {},'.format(filename))
        sys.exit(1)

    # HMAC Key
    dict_config = {}
    filename = os.path.join(config_dir, 'key')
    dict_config['key'] = get_config_from_file(filename, r_type='str')

    filename = os.path.join(config_dir, 'type')
    dict_config['type'] = get_config_from_file(filename, r_type='int')
    if dict_config['type'] < 0 and dict_config['type'] > 255:
        logger.error('unsuported d4 type: {}'.format(dict_config['type']))
        sys.exit(1)

    filename = os.path.join(config_dir, 'version')
    dict_config['version'] = get_config_from_file(filename, r_type='int')
    if dict_config['version'] < 0:
        logger.error('invalid version: {}'.format(dict_config['version']))
        sys.exit(1)

    filename = os.path.join(config_dir, 'snaplen')
    dict_config['snaplen'] = get_config_from_file(filename, r_type='int')
    if dict_config['snaplen'] <= 0:
        logger.error('invalid snaplen')
        sys.exit(1)

    # Sensor UUID
    dict_config['uuid'] = get_sensor_uuid(config_dir)
    return dict_config

def get_destination(config_dir, check_certificate=True):
    filename = os.path.join(config_dir, 'destination')
    if not os.path.isfile(filename):
        logger.error('destination file not found: {}'.format(filename))
        sys.exit(1)

    with open(filename, 'r') as f:
        destination = f.read().replace('\n', '')

    if destination == 'stdout':
        return destination
    # Get server address
    else:
        if not ':' in destination:
            # port = 80 ?
            logger.error('The destination is invalid')
            sys.exit(1)
        host, port = destination.rsplit(':', 1)
        # verify port
        try:
            port = int(port)
        except:
            logger.error('Invalid port')
            sys.exit(1)
        # verify address
        try:
            host = str(ipaddress.ip_address(host))
        except ValueError:
            # get IP host
            host = socket.gethostbyname(host)
            try:
                host = socket.gethostbyname(host)
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
        if check_certificate:
            cert_reqs_option = ssl.CERT_REQUIRED
        else:
            cert_reqs_option = ssl.CERT_NONE
        client_socket = ssl.wrap_socket(s, cert_reqs=cert_reqs_option, ca_certs=None, ssl_version=ssl.PROTOCOL_TLS)

        # TCP connect
        try:
            client_socket.connect((host, port))
        except ConnectionRefusedError:
            logger.error('Connection to {}:{} refused'.format(host, port))
            sys.exit(1)
        except ssl.SSLError as e:
            logger.error(e)
            sys.exit(1)
        return client_socket


def get_metaheader_json(config_dir):
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
    return json.dumps(metaheader).encode()

def read_and_send_data(config_dir, check_certificate):
    config = load_config(config_dir)
    destination = get_destination(config_dir, check_certificate=check_certificate)

    buffer = b''

    # handle extended type
    if config['type'] == 2 or config['type'] == 254:
        # send meadata json
        buffer = get_metaheader_json(config_dir)
        buffer = prepare_data(config['version'], 2, config['uuid'], config['key'], config['snaplen'], buffer, destination)
        pack_d4_data(config['version'], 2, config['uuid'],  config['key'], buffer, destination)
        # change type
        config['type'] = 254
        buffer = b''

    try:
        for data in io.open(sys.stdin.fileno(), mode='rb', buffering=0):

            if data:
                buffer = buffer + data
                buffer = prepare_data(config['version'], config['type'], config['uuid'], config['key'], config['snaplen'], buffer, destination)

        pack_d4_data(config['version'], config['type'], config['uuid'],  config['key'], buffer, destination)
        if not isinstance(destination, str):
            destination.shutdown(socket.SHUT_RDWR)

    # Send buffer content
    except KeyboardInterrupt:
        # Pack data
        buffer = prepare_data(config['version'], config['type'], config['uuid'], config['key'], config['snaplen'], buffer, destination)
        pack_d4_data(config['version'], config['type'], config['uuid'],  config['key'], buffer, destination)
        if not isinstance(destination, str):
            destination.shutdown(socket.SHUT_RDWR)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--config' ,help='config directory' ,type=str, dest='config', required=True)
    parser.add_argument('-cc', '--check_certificate' ,help='check server certificate', action="store_true")
    args = parser.parse_args()
    config_dir = args.config
    check_certificate = args.check_certificate

    read_and_send_data(config_dir, check_certificate)
