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
CURRENT_NAMESPACE = 'N/A'
SECRET_NAME = 'operator-secret'
SECRET_NAME_BACKUP = 'operator-secret-backup'
SECRET_OBJECT_OK = True
SMS_SECRET_NAME = 'operator-sms-secret'
SECRET_FILE_NAME = '/tmp/secret.json'
CURRENT_SECRET_OBJ = None
CURRENT_SECRET_OBJ_BACKUP = None
CHAIN_BASE_PATH = None
API_INSTANCE = None

OPERATOR_HEALTHY = Gauge("operator_healthy", 'check if the operator is healthy')
UNHEALTHY_VALIDATOR_NUM = Gauge("unhealthy_validator_num", 'number of current unhealthy validators')
UNHEALTHY_BOOTNODE_NUM = Gauge("unhealthy_bootnode_num", 'number of current unhealthy boot nodes')
UNHEALTHY_FULLNODE_NUM = Gauge("unhealthy_fullnode_num", 'number of current unhealthy full nodes')
SWAP_VALIDATOR_COUNT = Gauge("swap_validator_count", 'number of swapping validators session key action')
RESTART_GRANPA_COUNT = Gauge("restart_granpa_count", 'number of restarting validators granpa voting session')
TAINT_VALIDATOR_COUNT = Gauge("tainted_validator_count", 'number of tainted validators')
RESTART_BOOTNODE_COUNT = Gauge("restart_bootnode_count", 'number of restarting boot nodes')
RESTART_FULLNODE_COUNT = Gauge("restart_fullnode_count", 'number of restarting full nodes')


def get_pod_in_namespace(namespace, pod_name):
    try:
        pod_obj = API_INSTANCE.read_namespaced_pod(namespace=namespace, name=pod_name)
        return pod_obj
    except Exception:
        logging.warning(traceback.format_exc())
    return None


def run_cmd_in_namespaced_pod(namespace, pod_name, cmd):
    exec_command = [
        '/bin/bash',
        '-c',
        cmd]
    try:
        resp = kube_stream(API_INSTANCE.connect_get_namespaced_pod_exec,
                           pod_name,
                           namespace,
                           command=exec_command,
                           stderr=True, stdin=False,
                           stdout=True, tty=False)
        logging.info('pod exec cmd: ' + cmd)
        logging.debug(resp)
        return resp
    except Exception:
        logging.warning(traceback.format_exc())
    return ''


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


def run_cmd_until_ok(cmd, timeout=60):
    for i in range(int(timeout / 5)):
        rc, out = run_cmd(cmd)
        if rc != 0:
            time.sleep(5)
        else:
            return rc, out

    return -1, None


def http_get(url):
    try:
        r = requests.get(url, timeout=3)
        return r.text
    except:
        pass
    return "URL Unavailable"


# def http_post(http_url, post_json_body):
#     json_obj = convert_json_2_object(post_json_body)
#     response = requests.post(http_url, json=json_obj, headers={
#                              'Content-Type': 'application/json'})
#     if response.status_code == 200:
#         return True
#     else:
#         logging.warning(response)
#     return False

def get_secret_json_obj(namespace, secret_name):
    cmd = 'kubectl get secret {} -n {} -o json'.format(
        secret_name, namespace)
    rc, out = run_cmd(cmd)
    json_obj = convert_json_2_object(out)
    return json_obj


def get_current_secret_as_str():
    cmd = 'kubectl get secret {} -n {} -o json'.format(
        SECRET_NAME, CURRENT_NAMESPACE)
    rc, out = run_cmd(cmd)

    if rc != 0:
        logging.error('secret lost!!! try load secret from backup')
        cmd = 'kubectl get secret {} -n {} -o json'.format(
            SECRET_NAME_BACKUP, CURRENT_NAMESPACE)
        rc, out = run_cmd(cmd)

    json_obj = convert_json_2_object(out)
    try:
        secret_base64 = json_obj['data'][os.path.basename(SECRET_FILE_NAME)]
        secret_str = convert_base64_2_str(secret_base64)
        return secret_str
    except:
        pass


def backup_current_secret():
    if not CURRENT_SECRET_OBJ_BACKUP:
        logging.error('no secret at present!')
        return True

    current_secret = convert_object_2_json(CURRENT_SECRET_OBJ_BACKUP)

    with open(SECRET_FILE_NAME, 'w') as f:
        f.write(current_secret)

    cmd = 'kubectl delete secret --ignore-not-found=true {} -n {}'.format(
        SECRET_NAME_BACKUP, CURRENT_NAMESPACE)
    rc, out = run_cmd(cmd)
    cmd = 'kubectl create secret generic {} --from-file={} -n {}'.format(
        SECRET_NAME_BACKUP, SECRET_FILE_NAME, CURRENT_NAMESPACE)
    rc, out = run_cmd(cmd)
    return rc == 0


def create_update_operator_secret(session_key_json_obj):
    if backup_current_secret() is False:
        logging.error('failed to backup current secret')
        return False

    json_str = convert_object_2_json(session_key_json_obj)
    with open(SECRET_FILE_NAME, 'w') as f:
        f.write(json_str)

    cmd = 'kubectl delete secret --ignore-not-found=true {} -n {}'.format(
        SECRET_NAME, CURRENT_NAMESPACE)
    rc, out = run_cmd(cmd)

    cmd = 'kubectl create secret generic {} --from-file={} -n {}'.format(
        SECRET_NAME, SECRET_FILE_NAME, CURRENT_NAMESPACE)
    rc, out = run_cmd(cmd)
    return rc == 0


def get_namespace_for_current_pod():
    if not os.path.exists('/var/run/secrets/kubernetes.io/serviceaccount/namespace'):
        return 'az-ie-cennznet-validator-operator'

    cmd = 'cat /var/run/secrets/kubernetes.io/serviceaccount/namespace'
    rc, out = run_cmd(cmd)
    return out.strip()


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


# def get_pod_ip_real(namespace, pod_name):
#     cmd = 'kubectl get pod {} -n {} -o json'.format(pod_name, namespace)
#     rc, out = run_cmd(cmd)
#     if rc != 0:
#         return None
#     try:
#         json_obj = convert_json_2_object(out)
#         pod_ip = jmespath.search('status.podIP', json_obj)
#         return pod_ip
#     except Exception:
#         logging.warning(traceback.format_exc())


def get_pod_ip(namespace, pod_name):
    pod_obj = get_pod_in_namespace(namespace, pod_name)
    if pod_obj:
        pod_ip = pod_obj.status.pod_ip
        if pod_ip:
            return pod_ip


# def get_pod_restart_count(namespace, pod_name):
#     cmd = 'kubectl get pod {} -n {} -o json'.format(pod_name, namespace)
#     rc, out = run_cmd(cmd)
#     try:
#         json_obj = convert_json_2_object(out)
#         restart_count = jmespath.search(
#             'status.containerStatuses[0].restartCount', json_obj)
#         if restart_count is None:
#             return "-2"
#         return restart_count
#     except Exception:
#         logging.warning(traceback.format_exc())
#     return "-1"


def extract_pods_ips():
    for record in CURRENT_SECRET_OBJ:
        namespace = record['namespace']
        pod_name = record['pod_name']

        pod_ip = get_pod_ip(namespace, pod_name)
        record['pod_ip'] = pod_ip
        # record['restart_count'] = get_pod_restart_count(namespace, pod_name)
        # logging.warning(namespace, pod_name, pod_ip)


def get_max_best_finalized_number():
    best, finalized, sync_target = 0, 0, 0
    if CURRENT_SECRET_OBJ and len(CURRENT_SECRET_OBJ) > 0:
        for record in CURRENT_SECRET_OBJ:
            tmp_best = int(record.get('substrate_block_height_best', '-3'))
            tmp_finalized = int(record.get(
                'substrate_block_height_finalized', '-3'))
            tmp_sync_target = int(record.get('substrate_block_height_sync_target', '-3'))
            if tmp_best > best:
                best = tmp_best
            if tmp_finalized > finalized:
                finalized = tmp_finalized
            if tmp_sync_target > sync_target:
                sync_target = tmp_sync_target

    return best, finalized, tmp_sync_target


def update_node_status(best, finalized, sync_target):
    if CURRENT_SECRET_OBJ and len(CURRENT_SECRET_OBJ) > 0:
        for record in CURRENT_SECRET_OBJ:
            tmp_best = int(record.get('substrate_block_height_best', '-4'))
            tmp_finalized = int(record.get(
                'substrate_block_height_finalized', '-4'))
            # tmp_sync_target = int(record.get('substrate_block_height_sync_target', '-4'))
            if (best - tmp_best) > 6 or (finalized - tmp_finalized) > 6 or (sync_target - tmp_best) > 6:
                record['healthy'] = False
            else:
                record['healthy'] = True
            if 'validator' != record['node_type'] and record['healthy'] is False:
                current_best = int(record.get('substrate_block_height_best', 0))
                prev_best = int(record.get('prev_best', 0))
                curent_finalized = int(record.get('substrate_block_height_finalized', 0))
                prev_finalized = int(record.get('prev_finalized', 0))
                if (current_best - prev_best) > 6 and (curent_finalized - prev_finalized) > 6:
                    record['healthy'] = True


def extract_pods_metrics():
    for record in CURRENT_SECRET_OBJ:
        namespace = record['namespace']
        pod_name = record['pod_name']
        pod_ip = record['pod_ip']
        record['substrate_block_height_best'] = '-5'
        record['substrate_block_height_finalized'] = '-5'
        record['substrate_block_height_sync_target'] = '-5'
        if not pod_ip:
            logging.error(
                '{}/{} pod ip {}, cannot extract metrics'.format(namespace, pod_name, pod_ip))
            continue
        pod_metrics_url = 'http://{}:{}/metrics'.format(pod_ip, 9615)
        try:
            pod_metrics_txt = http_get(pod_metrics_url)

            lines = pod_metrics_txt.split('\n')

            for line in lines:
                if line.startswith('substrate_block_height{status="best"}'):
                    record['substrate_block_height_best'] = line.split()[-1]
                elif line.startswith('substrate_block_height{status="finalized"}'):
                    record['substrate_block_height_finalized'] = line.split()[-1]
                elif line.startswith('substrate_block_height{status="sync_target"}'):
                    record['substrate_block_height_sync_target'] = line.split()[-1]

        except Exception:
            logging.warning(traceback.format_exc())


def show_data_frame():
    pd.set_option('display.max_rows', None)
    pd.set_option('display.max_columns', None)
    pd.set_option('display.width', None)
    df = pd.DataFrame(CURRENT_SECRET_OBJ, columns=[
        'namespace', 'pod_name', 'node_type', 'substrate_block_height_best', 'substrate_block_height_finalized',
        'substrate_block_height_sync_target', 'state', 'healthy', 'tainted'])
    logging.warning('\n' + str(df))

    UNHEALTHY_VALIDATOR_NUM.set(0)
    UNHEALTHY_BOOTNODE_NUM.set(0)
    UNHEALTHY_FULLNODE_NUM.set(0)
    TAINT_VALIDATOR_COUNT.set(0)
    for record in CURRENT_SECRET_OBJ:
        if record.get('tainted') is True:
            TAINT_VALIDATOR_COUNT.inc(1)

        if record.get('healthy') is False:
            if 'validator' == record['node_type']:
                UNHEALTHY_VALIDATOR_NUM.inc(1)
            elif 'bootnode' == record['node_type']:
                UNHEALTHY_BOOTNODE_NUM.inc(1)
            elif 'fullnode' == record['node_type']:
                UNHEALTHY_FULLNODE_NUM.inc(1)


def upload_subkey_to_pod(namespace, pod_name):
    kube_cmd = 'ls -l /subkey && echo HELLOWORLD'
    out = run_cmd_in_namespaced_pod(namespace, pod_name, kube_cmd)
    # cmd = 'kubectl -n {} exec {} -- ls -l /subkey'.format(namespace, pod_name)
    # rc, out = run_cmd(cmd)
    if 'HELLOWORLD' not in out:
        cmd = 'which subkey'
        rc, out = run_cmd(cmd)
        cmd = 'kubectl -n {} cp {} {}:/subkey'.format(
            namespace, out.strip(), pod_name)
        rc, out = run_cmd_until_ok(cmd)
        cmd = 'kubectl -n {} exec {} -- chmod +x /subkey'.format(
            namespace, pod_name)
        rc, out = run_cmd_until_ok(cmd)


def insert_key_type(namespace, pod_name, key_type, node_session_key, keyscheme='Sr25519'):
    upload_subkey_to_pod(namespace, pod_name)
    cmd = 'kubectl -n {} exec {} -- /subkey insert --key-type {} --suri="{}" --scheme {} --base-path={}'.format(
        namespace, pod_name, key_type, node_session_key, keyscheme, CHAIN_BASE_PATH)
    rc, out = run_cmd_until_ok(cmd)
    return rc


def restart_granpa_voting(namespace, pod_name):
    cmd = 'kubectl -n {} exec {} -- which curl'.format(namespace, pod_name)
    rc, out = run_cmd(cmd)
    if rc != 0 or 'not found' in out:
        cmd = 'kubectl -n {} exec {} -- /bin/bash -c \'apt update; apt install -y curl\''.format(namespace, pod_name)
        rc, out = run_cmd_until_ok(cmd)
    else:
        logging.info('{}/{} has curl installed!!!'.format(namespace, pod_name))

    restart_cmd = '''
            curl -s -H 'Content-Type: application/json' -d '{ "jsonrpc": "2.0", "method":"grandpa_restartVoter", "params":[], "id": 1 }' http://localhost:9933
            '''
    logging.info('{}/{} curl is available'.format(namespace, pod_name))
    curl_out = run_cmd_in_namespaced_pod(namespace, pod_name, restart_cmd.strip())
    logging.warning(curl_out)
    if 'jsonrpc' in curl_out and 'error' not in curl_out:
        RESTART_GRANPA_COUNT.inc(1)


def insert_keys(namespace, pod_name, node_session_key):
    rc = insert_key_type(namespace, pod_name, 'audi', node_session_key)
    rc2 = insert_key_type(namespace, pod_name, 'babe', node_session_key)
    rc3 = insert_key_type(namespace, pod_name, 'imon', node_session_key)
    rc4 = insert_key_type(namespace, pod_name, 'gran', node_session_key, 'Ed25519')
    SWAP_VALIDATOR_COUNT.inc(1)
    if (rc + rc2 + rc3 + rc4) > 0:
        logging.error('failed to insert session key to {}/{}'.format(namespace, pod_name))
        return
    else:
        logging.warning('{}/{} got the new session key'.format(namespace, pod_name))
        restart_granpa_voting(namespace, pod_name)


def remove_session_keys(namespace, pod_name):
    cmd = 'kubectl exec -n {} {} -- /bin/bash -c \'rm -f {}/keystore/*\''.format(namespace, pod_name, CHAIN_BASE_PATH)
    return run_cmd_until_ok(cmd, timeout=30)


def kill_pod(namespace, pod_name):
    logging.warning(f'killing pod {namespace}/{pod_name}....')
    cmd = 'kubectl delete pod -n {} {}'.format(namespace, pod_name)
    rc, out = run_cmd_until_ok(cmd)


def convert_str_2_date(date_time_str):
    try:
        date_time_obj = datetime.datetime.strptime(date_time_str, '%d/%m/%Y %H:%M')
        return date_time_obj
    except:
        logging.warning('cannot parse:', date_time_str)
    return datetime.datetime(1970, 1, 1, 0, 0)


def convert_date_2_str(dateobj):
    dt_str = dateobj.strftime('%d/%m/%Y %H:%M')
    return dt_str


def restart_stalled_node_if_nessesary(record):
    node_type = record['node_type']
    if node_type not in ('bootnode', 'fullnode'):
        logging.warning(f'node type {node_type} is not recognized!')
        return
    healthy = record['healthy']
    if healthy is True:
        return
    prev_restart_dt_str = record.get('restart_datetime', '01/01/1970 00:00')
    prev_restart_dt = convert_str_2_date(prev_restart_dt_str)
    now = datetime.datetime.now()
    max_interval = datetime.timedelta(minutes=30)
    if (now - prev_restart_dt) > max_interval:
        record['restart_datetime'] = convert_date_2_str(now)
        namespace, pod_name, pod_ip = record['namespace'], record['pod_name'], record['pod_ip']
        if pod_ip is None or len(pod_ip) <= 0:
            logging.error('{}/{} is not running, cannot kill/restart it'.format(namespace, pod_name))
            return
        kill_pod(namespace, pod_name)
        if node_type == 'bootnode':
            RESTART_BOOTNODE_COUNT.inc(1)
        elif node_type == 'fullnode':
            RESTART_FULLNODE_COUNT.inc(1)


def loop_work():
    global SECRET_OBJECT_OK
    global CURRENT_SECRET_OBJ
    global CURRENT_SECRET_OBJ_BACKUP

    secret_string = get_current_secret_as_str()
    CURRENT_SECRET_OBJ = convert_json_2_object(secret_string)
    CURRENT_SECRET_OBJ_BACKUP = convert_json_2_object(secret_string)

    if CURRENT_SECRET_OBJ and len(CURRENT_SECRET_OBJ) > 0:
        SECRET_OBJECT_OK = True
        extract_pods_ips()
        extract_pods_metrics()
        best, finalized, sync_target = get_max_best_finalized_number()
        update_node_status(best, finalized, sync_target)

        suspended_records = []
        idle_healthy_validator_records = []
        boot_full_node_records = []

        # verify the current setup
        verify_session_keys_on_nodes()
        show_data_frame()

        for record in CURRENT_SECRET_OBJ:
            if record.get('tainted'):
                logging.error('cannot continue to process, record is tainted! \n {}'.format(record))
                return

        for record in CURRENT_SECRET_OBJ:
            node_type = record['node_type']
            if node_type in ('bootnode', 'fullnode'):
                boot_full_node_records.append(record)
                continue
            if 'validator' != node_type:
                logging.error(f'something wrong, new node type?? {node_type}')
                continue

            if record['state'] == 'suspension':
                suspended_records.append(record)
                continue
            namespace, pod_name = record['namespace'], record['pod_name']
            if record['state'] == 'staking' and record['healthy'] is False:
                pod_ip = record['pod_ip']
                if pod_ip is None or len(pod_ip) <= 0:
                    logging.error('{}/{} is not running, cannot remove the key from it'.format(namespace, pod_name))
                    continue

                logging.warning(
                    '{}/{} is unhealthy, need to remove the session key from it....'.format(namespace, pod_name))

                # make sure there is no key files left
                rc, out = remove_session_keys(namespace, pod_name)
                if rc != 0:
                    logging.error(
                        'failed to delete the keystore directory on pod {}/{}, skip swapping it'.format(namespace,
                                                                                                        pod_name))
                    continue

                logging.warning('need to kill the pod to force it to restart...{}/{}'.format(namespace, pod_name))
                kill_pod(namespace, pod_name)

                record['state'] = 'suspension'
                suspended_records.append(record)
            elif record['state'] == 'idle' and record['healthy'] is True:
                if 'validator' == record['node_type']:
                    idle_healthy_validator_records.append(record)

        for record in suspended_records:
            if len(idle_healthy_validator_records) <= 0:
                logging.warning('no healthy idle validator to swap to!!!')
                break

            healthy_validator_record = idle_healthy_validator_records.pop()
            if healthy_validator_record:
                record['state'] = 'idle'
                healthy_validator_record['state'] = 'staking'
                session_key = healthy_validator_record['session_key'] = record['session_key']
                record['session_key'] = ""
                old_namespace, old_pod_name = record[
                                                  'namespace'], record['pod_name']
                namespace, pod_name, pod_ip = healthy_validator_record[
                                                  'namespace'], healthy_validator_record['pod_name'], \
                                              healthy_validator_record['pod_ip']
                logging.warning(
                    'transfer session key from {}/{} to {}/{}'.format(old_namespace, old_pod_name, namespace, pod_name))
                insert_keys(namespace, pod_name, session_key)


        for record in boot_full_node_records:
            restart_stalled_node_if_nessesary(record)

        for record in CURRENT_SECRET_OBJ:
            record['prev_best'] = record['substrate_block_height_best']
            record['prev_finalized'] = record['substrate_block_height_finalized']
            record['prev_sync_target'] = record['substrate_block_height_sync_target']
            if record.get('substrate_block_height_best'):
                del record['substrate_block_height_best']
            if record.get('substrate_block_height_finalized'):
                del record['substrate_block_height_finalized']
            if record.get('substrate_block_height_sync_target'):
                del record['substrate_block_height_sync_target']
            if record.get('pod_ip'):
                del record['pod_ip']

        create_update_operator_secret(CURRENT_SECRET_OBJ)
    else:
        SECRET_OBJECT_OK = False
    # reset secret obj
    CURRENT_SECRET_OBJ = None


_to_esc = re.compile(r'\s|[]()[]')


def _esc_char(match):
    return '\\' + match.group(0)


def my_escape(name):
    return _to_esc.sub(_esc_char, name)


def extract_chain_base_path():
    global CHAIN_BASE_PATH
    global CURRENT_SECRET_OBJ

    if CHAIN_BASE_PATH:
        return
    if CURRENT_SECRET_OBJ and len(CURRENT_SECRET_OBJ) > 0:
        for record in CURRENT_SECRET_OBJ:
            namespace, pod_name = record['namespace'], record['pod_name']
            cmd = 'kubectl -n {} exec {} -- ls /mnt/cennznet/chains/'.format(namespace, pod_name)
            rc, out = run_cmd(cmd)
            if rc != 0:
                logging.warning(out)
                continue
            base_path = os.path.join('/mnt/cennznet/chains/', out.strip())
            CHAIN_BASE_PATH = my_escape(base_path)
            if len(CHAIN_BASE_PATH) > 0:
                break


def verify_session_keys_on_nodes():
    any_wrong = False
    if CURRENT_SECRET_OBJ and len(CURRENT_SECRET_OBJ) > 0:
        for record in CURRENT_SECRET_OBJ:
            if 'validator' != record['node_type']:
                continue

            namespace, pod_name, pod_ip, session_key = record['namespace'], record['pod_name'], record['pod_ip'], \
                                                       record['session_key']
            if pod_ip is None:
                logging.warning('{}/{} is not running!'.format(namespace, pod_name))
                continue
            record['tainted'] = False

            kube_cmd = 'ls {}/keystore/'.format(CHAIN_BASE_PATH)
            cmd_out = run_cmd_in_namespaced_pod(namespace, pod_name, kube_cmd)

            lines = []
            trimmed_out = cmd_out.strip()
            if len(trimmed_out) > 0:
                lines = trimmed_out.split('\n')
            file_count = len(lines)

            if file_count == 0:
                logging.info('{}/{} no session key files on this node'.format(namespace, pod_name))
                if len(session_key) > 0 and record['state'] != 'suspension':
                    logging.error('{}/{} is supposed to stake/suspend, but session key is not inserted/removed.'.format(
                        namespace, pod_name))
                    record['tainted'] = True
                    any_wrong = True
                continue
            elif file_count == 4:
                if len(session_key) <= 0:
                    logging.error('no session key assigned, but session key files exist!!!')
                    record['tainted'] = True
                    any_wrong = True
                for i in range(4):
                    file_name = lines[i]
                    cmd = 'cat {}/keystore/{}'.format(CHAIN_BASE_PATH, file_name)
                    # rc, out = run_cmd_until_ok(cmd)
                    out = run_cmd_in_namespaced_pod(namespace, pod_name, cmd)
                    if session_key not in out:
                        logging.error(
                            '{}/{} session key mismatch between record in secret and the key file  on file: {}'.format(
                                namespace, pod_name, file_name))
                        record['tainted'] = True
                        any_wrong = True
                    else:
                        logging.info(
                            '{}/{} session key in file: {}'.format(namespace, pod_name, file_name))
            else:
                logging.error(
                    '{}/{} session keys files not complete length: {} '.format(namespace, pod_name, len(lines)))
                record['tainted'] = True
                any_wrong = True
                continue
    return any_wrong



def main_thread():
    global CURRENT_NAMESPACE
    global CURRENT_SECRET_OBJ
    global API_INSTANCE

    try:
        kube_config.load_incluster_config()
        API_INSTANCE = core_v1_api.CoreV1Api()

        CURRENT_NAMESPACE = get_namespace_for_current_pod()
        secret_str = get_current_secret_as_str()
        CURRENT_SECRET_OBJ = convert_json_2_object(secret_str)
        extract_chain_base_path()

        logging.info('API_INSTANCE: ' + str(API_INSTANCE))
        logging.debug('CURRNET_SECRET_OBJ: ' + str(CURRENT_SECRET_OBJ))
        logging.info('CHAIN_BASE_PATH:' + str(CHAIN_BASE_PATH))

        if CHAIN_BASE_PATH is None:
            logging.error('cannot find the chain base path, exit!!!')
            sys.exit(-100)

        while True:
            signal_file = os.path.join(USER_HOME, 'stop_operator')
            if os.path.exists(signal_file):
                logging.error(f'Found signal file {signal_file}, operator paused!')
            else:
                loop_work()
            sys.stderr.flush()
            sys.stdout.flush()
            time.sleep(10)
    except Exception:
        logging.warning(traceback.format_exc())


FLASK_APP = Flask(__name__)
MAIN_THREAD = Thread(target=main_thread, args=())


@FLASK_APP.route("/")
def flask_root():
    if MAIN_THREAD.is_alive() and SECRET_OBJECT_OK:
        OPERATOR_HEALTHY.set(1)
    else:
        OPERATOR_HEALTHY.set(0)
    return Response('OK', mimetype="text/plain")


@FLASK_APP.route("/metrics")
def flask_metrics():
    return Response(prometheus_client.generate_latest(), mimetype="text/plain")


if __name__ == '__main__':
    try:
        parser = argparse.ArgumentParser(
            description='Dynamically manage the validator session keys in the current kubernetes cluster')
        parser.add_argument('-l', '--log_level', default='INFO', help='logger level')
        args = parser.parse_args()
        log_level = getattr(args, 'log_level')

        logging.basicConfig(
            level=log_level,
            format="%(asctime)s %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
            stream=sys.stderr)

        MAIN_THREAD.start()
        # FLASK_APP.logger.disabled = Trueconvert_str_to_datetime
        logger_werkzeug = logging.getLogger('werkzeug')
        logger_werkzeug.disabled = True
        FLASK_APP.run(host='0.0.0.0', port=8080)
    except Exception:
        logging.warning(traceback.format_exc())
