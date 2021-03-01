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
from kubernetes import config as kube_config
from kubernetes.client.api import core_v1_api
from kubernetes.stream import stream as kube_stream
import prometheus_client
from prometheus_client import Gauge
# from flask_webserver import Response, Flask
from threading import Thread
import logging
import argparse

CHAIN_NAME = 'Azalea'

def run_cmd(cmd, work_dir=None):
    print('CMD: ' + cmd)
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True, cwd=work_dir)
    result = process.communicate()[0]
    print('{}'.format(result.decode()))
    return process.returncode, result.decode()


ALL_NODES = [
    {"kube_ctx": "aks-mainnet-ie", "namespace": "az-ie-cennznet-validators-blue", "pod_name": "az-ie-cennznet-v-b-0"},
    {"kube_ctx": "aks-mainnet-ie", "namespace": "az-ie-cennznet-validators-blue", "pod_name": "az-ie-cennznet-v-b-1"},
    {"kube_ctx": "aks-mainnet-ie", "namespace": "az-ie-cennznet-validators-blue", "pod_name": "az-ie-cennznet-v-b-2"},
    {"kube_ctx": "aks-mainnet-ie", "namespace": "az-ie-cennznet-validators-blue", "pod_name": "az-ie-cennznet-v-b-3"}
,

    {"kube_ctx": "aks-mainnet-ie", "namespace": "az-ie-cennznet-validators-green", "pod_name": "az-ie-cennznet-v-g-0"},
    {"kube_ctx": "aks-mainnet-ie", "namespace": "az-ie-cennznet-validators-green", "pod_name": "az-ie-cennznet-v-g-1"},
    {"kube_ctx": "aks-mainnet-ie", "namespace": "az-ie-cennznet-validators-green", "pod_name": "az-ie-cennznet-v-g-2"},
    {"kube_ctx": "aks-mainnet-ie", "namespace": "az-ie-cennznet-validators-green", "pod_name": "az-ie-cennznet-v-g-3"},

    {"kube_ctx": "eks-prod", "namespace": "aws-sg-cennznet-validators-blue", "pod_name": "aws-sg-cennznet-v-b-0"},
    {"kube_ctx": "eks-prod", "namespace": "aws-sg-cennznet-validators-blue", "pod_name": "aws-sg-cennznet-v-b-1"},
    {"kube_ctx": "eks-prod", "namespace": "aws-sg-cennznet-validators-blue", "pod_name": "aws-sg-cennznet-v-b-2"},
    {"kube_ctx": "eks-prod", "namespace": "aws-sg-cennznet-validators-blue", "pod_name": "aws-sg-cennznet-v-b-3"},

    {"kube_ctx": "eks-prod", "namespace": "aws-sg-cennznet-validators-green", "pod_name": "aws-sg-cennznet-v-g-0"},
    {"kube_ctx": "eks-prod", "namespace": "aws-sg-cennznet-validators-green", "pod_name": "aws-sg-cennznet-v-g-1"},
    {"kube_ctx": "eks-prod", "namespace": "aws-sg-cennznet-validators-green", "pod_name": "aws-sg-cennznet-v-g-2"},
    {"kube_ctx": "eks-prod", "namespace": "aws-sg-cennznet-validators-green", "pod_name": "aws-sg-cennznet-v-g-3"},

    {"kube_ctx": "aks-mainnet-us", "namespace": "az-us-cennznet-validators-blue", "pod_name": "az-us-cennznet-v-b-0"},
    {"kube_ctx": "aks-mainnet-us", "namespace": "az-us-cennznet-validators-blue", "pod_name": "az-us-cennznet-v-b-1"},
    {"kube_ctx": "aks-mainnet-us", "namespace": "az-us-cennznet-validators-blue", "pod_name": "az-us-cennznet-v-b-2"},
    {"kube_ctx": "aks-mainnet-us", "namespace": "az-us-cennznet-validators-blue", "pod_name": "az-us-cennznet-v-b-3"},

    {"kube_ctx": "aks-mainnet-us", "namespace": "az-us-cennznet-validators-green", "pod_name": "az-us-cennznet-v-g-0"},
    {"kube_ctx": "aks-mainnet-us", "namespace": "az-us-cennznet-validators-green", "pod_name": "az-us-cennznet-v-g-1"},
    {"kube_ctx": "aks-mainnet-us", "namespace": "az-us-cennznet-validators-green", "pod_name": "az-us-cennznet-v-g-2"},
    {"kube_ctx": "aks-mainnet-us", "namespace": "az-us-cennznet-validators-green", "pod_name": "az-us-cennznet-v-g-3"}

]

def port_forward_process_raw(context, ns, pod):
    cmd = 'k config use-context {}'.format(context)
    rc, out = run_cmd(cmd)
    cmd = 'kubectl config current-context'
    rc, out = run_cmd(cmd)
    if context not in out:
        print('Failed to switch context....')
        return None
    cmd = 'killall -9 kubectl'
    rc, out = run_cmd(cmd)

    #k -n az-us-cennznet-validators-blue  port-forward az-us-cennznet-v-b-0 9933:9933 9944:9944
    cmd_args = ['/usr/local/bin/kubectl', '-n', ns, 'port-forward', pod, '9944:9944', '9933:9933']
    print('Run process: ', cmd_args)
    forward_process = subprocess.Popen(cmd_args)
    time.sleep(5)
    cmd = 'curl http://localhost:9933'
    rc, out = run_cmd(cmd)
    if 'Used HTTP Method is not allowed' in out:
        return forward_process
    else:
        print('port forward process error')
    return None

def get_node_keys():
    stash_acct, session_pub_key, gran_pub_key = None, None, None
    cmd = 'bin/cennz-cli --endpoint=ws://localhost:9944 --run=./scripts/node-info.js'
    rc, out = run_cmd(cmd, work_dir='/Users/maochuanli/centrality.projects/cennznet-jordy-cli')
    lines = out.split('\n')
    for line in lines:
        # print(line)
        if 'babe' in line:
            line_sub = line.strip().split()
            session_pub_key = line_sub[-1]
        elif 'connected to stash' in line:
            line_sub = line.strip().split()
            stash_acct = line_sub[-1]
        elif 'gran' in line:
            line_sub = line.strip().split()
            gran_pub_key = line_sub[-1]
    if 'fail' in out:
        print('......................try to manual run command......', out)
        time.sleep(30)
    return stash_acct, session_pub_key, gran_pub_key

def port_forward_process(context, ns, pod):
    p = port_forward_process_raw(context, ns, pod)
    while not p:
        print('sleep 5 seconds and try again to port forward.....')
        time.sleep(5)
        p = port_forward_process_raw(context, ns, pod)

    return p

def verify_keys(context, ns, pods, keys, public_session_keys):
    cmd = 'k config use-context {}'.format(context)
    rc, out = run_cmd(cmd)
    cmd = 'kubectl config current-context'
    rc, out = run_cmd(cmd)
    if context not in out:
        print('Failed to switch context....')
        return None

    for index in range(len(pods)):
        pod = pods[index]
        key = keys[index]
        key_ss58 = public_session_keys[index]
        print('namespace: {}, pod: {}'.format(ns, pod))
        cmd = 'k exec -n {} {} -- ls /mnt/cennznet/chains/CENNZnet\ {}\ V1/keystore/'.format(ns, pod, CHAIN_NAME)
        rc, out = run_cmd(cmd)
        lines = out.strip().split('\n')
        if len(lines) < 4:
            print('session key is NOT inserted here! {} {} with key: [{}]'.format(ns, pod, key))
            continue

        first_line = lines[0]
        cmd = 'k exec -n {} {} -- cat /mnt/cennznet/chains/CENNZnet\ {}\ V1/keystore/{}'.format(ns, pod, CHAIN_NAME, first_line.strip())
        rc, out = run_cmd(cmd)
        if key in out:
            print('ok with session key files')
            if 'empty' in key_ss58:
                print('no need verify session key with Jordy tool')
                continue
            p = port_forward_process(context, ns, pod)
            if not p:
                sys.exit(-1)
            stash_acct, babe_key, gran_key = get_node_keys()
            p.kill()
            p.wait()

            if key_ss58 in babe_key:
                print('<<<<<<<<<<<<< dynamic verification ok {}/{}'.format(ns, pod))
            else:
                print('############# failure to dynamic verify session key: {} {}'.format(ns, pod))
        else:
            print('%%%%%%%%%%% Pod does not have proper key:  key : {} vs actual value: {}'.format(key, out))

def convert_object_2_json(python_object):
    try:
        return json.dumps(python_object,indent=4)
    except Exception:
        logging.warning(traceback.format_exc())

def main():
    for node in ALL_NODES:
        ctx = node['kube_ctx']
        ns = node['namespace']
        pod = node['pod_name']
        print(ctx, ns, pod)
        p = port_forward_process(ctx, ns, pod)
        if not p:
            sys.exit(-1)
        stash_acct, session_key, gran_key = get_node_keys()
        node['stash'] = stash_acct
        node['babe'] = session_key
        node['gran'] = gran_key
        p.kill()
        p.wait()
        print(ctx, ns, pod, stash_acct, session_key)

    print(convert_object_2_json(ALL_NODES))
    df = show_data_frame(ALL_NODES)
    print(df)


def show_data_frame(OBJ):
    pd.set_option('display.max_rows', None)
    pd.set_option('display.max_columns', None)
    pd.set_option('display.width', None)
    df = pd.DataFrame(OBJ, columns=['kube_ctx', 'namespace', 'pod_name', 'stash', 'babe','gran'])
    return df


if __name__ == '__main__':
    main()