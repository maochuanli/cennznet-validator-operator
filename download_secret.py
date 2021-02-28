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
from kubernetes import config as kube_config
from kubernetes.client.api import core_v1_api
from kubernetes.stream import stream as kube_stream
import prometheus_client
from prometheus_client import Gauge
from flask import Response, Flask
from flask import request as flask_request
from threading import Thread
import logging
import argparse
from os.path import expanduser
USER_HOME = expanduser("~")

def run_cmd(cmd):
    logging.info('CMD: ' + cmd)
    process = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)
    result = process.communicate()[0]
    result_txt = result.decode()
    if process.returncode != 0:
        logging.warning('{},{},{}'.format(process.returncode, cmd, result_txt))
    else:
        logging.debug('{},{}'.format(process.returncode, result_txt))
    return process.returncode, result_txt




def convert_base64_2_str(base64_message):
    base64_bytes = base64_message.encode('ascii')
    message_bytes = base64.b64decode(base64_bytes)
    message = message_bytes.decode('ascii')
    return message


def convert_str_2_base64(message):
    message_bytes = message.encode('ascii')
    base64_bytes = base64.b64encode(message_bytes)
    base64_message = base64_bytes.decode('ascii')
    return base64_message


def convert_json_2_object(json_str):
    try:
        return json.loads(json_str)
    except Exception:
        logging.info(traceback.format_exc())


def convert_object_2_json(python_object):
    try:
        return json.dumps(python_object)
    except Exception:
        logging.info(traceback.format_exc())
        


def get_current_secret_as_str(namespace, secret_name, secret_key):
    cmd = 'kubectl get secret {} -n {} -o json'.format(secret_name, namespace)
    rc, out = run_cmd(cmd)
    json_obj = convert_json_2_object(out)
    try:
        secret_base64 = json_obj['data'][os.path.basename(secret_key)]
        secret_str = convert_base64_2_str(secret_base64)
        return secret_str
    except:
        pass

def switch_context(context):
    cmd = f'kubectl config use-context {context}'
    run_cmd(cmd)

    cmd = 'kubectl config current-context'
    rc, out = run_cmd(cmd)
    if context == out.strip():
        return True

    return False

def write_secret(context, namespace, secret_name, secret_key):
    if switch_context(context):
        secret = get_current_secret_as_str(namespace, secret_name, secret_key)
        secret_obj = convert_json_2_object(secret)
        pretty_json = json.dumps(secret_obj, indent=4)
        with open(os.path.join(USER_HOME, f'{namespace}.json'), 'w') as f:
            f.write(pretty_json)
        logging.info(pretty_json)

def main():
    if switch_context('eks-prod'):
        context, namespace, secret_name, secret_key = 'eks-prod', 'aws-sg-cennznet-validators-operator', 'operator-secret-backup', 'secret.json'
        write_secret(context, namespace, secret_name, secret_key)

    if switch_context('aks-mainnet-us'):
        context, namespace, secret_name, secret_key = 'aks-mainnet-us', 'az-us-cennznet-validators-operator', 'operator-secret-backup', 'secret.json'
        write_secret(context, namespace, secret_name, secret_key)

    if switch_context('aks-mainnet-ie'):
        context, namespace, secret_name, secret_key = 'aks-mainnet-ie', 'az-ie-cennznet-validators-operator', 'operator-secret-backup', 'secret.json'
        write_secret(context, namespace, secret_name, secret_key)


if __name__ == '__main__':
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        stream=sys.stderr)
    main()
    notices = f'''
    kubectl config use-context aks-mainnet-us
        kubectl delete secret operator-secret -n az-us-cennznet-validators-operator
    kubectl create secret generic operator-secret -n az-us-cennznet-validators-operator --from-file=secret.json={USER_HOME}/az-us-cennznet-validators-operator.json
    
    kubectl config use-context aks-mainnet-ie
        kubectl delete secret operator-secret -n az-ie-cennznet-validators-operator
    kubectl create secret generic operator-secret -n az-ie-cennznet-validators-operator --from-file=secret.json={USER_HOME}/az-ie-cennznet-validators-operator.json
    
    kubectl config use-context eks-prod
        kubectl delete secret operator-secret -n az-us-cennznet-validators-operator
    kubectl create secret generic operator-secret -n aws-sg-cennznet-validators-operator --from-file=secret.json={USER_HOME}/aws-sg-cennznet-validators-operator.json
    
    
    '''
    logging.info(notices)