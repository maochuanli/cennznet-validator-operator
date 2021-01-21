from prometheus_client import start_http_server
import os
import sys
import time
import subprocess
import json
import base64
import datetime
import traceback
import jmespath
import requests
import pandas as pd
import re

def insert_key_gran(node_ip, key_type, node_session_key, node_key_public_key):
    gran_request = '''
    {{
    "jsonrpc": "2.0",
    "method": "author_insertKey",
    "params": [
      "{}",
      "{}",
      "{}"
    ],
    "id": 0
    }}
    '''.format(key_type, node_session_key, node_key_public_key)
    print(gran_request)
    # post_json_body = gran_request.format(key_type, node_session_key, node_key_public_key)
    # print(post_json_body)
def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)
    sys.stderr.flush()


def run_cmd(cmd):
    eprint('CMD: ' + cmd)
    process = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)
    result = process.communicate()[0]
    result_txt = result.decode()
    if process.returncode != 0:
        eprint('{},{}'.format(process.returncode, result_txt))
    return process.returncode, result_txt

if __name__ == "__main__":
    cmd = 'kubectl -n dev-rata-validators-green exec d-rata-v-green-0 -- ls /mnt/cennznet/chains/CENNZnet\ Rata\ V1/keystore/'
    rc, out = run_cmd(cmd)

    lines = []
    if len(out.strip()) > 0:
        lines = out.strip().split('\n')
    file_count = len(lines)
    eprint('file count: ', file_count)
    eprint('lines: ', lines)

    cmd = 'kubectl -n dev-rata-validators-blue exec d-rata-v-blue-2 -- ls /mnt/cennznet/chains/CENNZnet\ Rata\ V1/keystore/'
    rc, out = run_cmd(cmd)

    lines = []
    if len(out.strip()) > 0:
        lines = out.strip().split('\n')
    file_count = len(lines)

    eprint('file count: ', file_count)
    eprint('lines: ', lines)