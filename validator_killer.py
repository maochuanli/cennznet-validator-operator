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
import random

def run_cmd(cmd):
    print('CMD: ' + cmd)
    process = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)
    result = process.communicate()[0]
    result_txt = result.decode()
    if process.returncode != 0:
        print('{},{}'.format(process.returncode, result_txt))
    return process.returncode, result_txt

def kill_pod(namespace, pod_name):
    cmd = 'kubectl delete pod -n {} {}'.format(namespace, pod_name)
    rc, out = run_cmd(cmd)

def main():
    with open('/tmp/secret.json', 'r') as f:
        obj = json.loads(f.read())
        while True:
            index = random.randrange(len(obj))
            print('rand', index)
            record = obj[index]
            ns, pod = record['namespace'], record['pod_name']
            print('killing pod: ', ns, pod)
            kill_pod(ns, pod)
            time.sleep(60)

if __name__ == "__main__":
    main()