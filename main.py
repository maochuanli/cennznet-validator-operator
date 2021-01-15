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

CURRENT_NAMESPACE = 'N/A'
SECRET_NAME = 'operator-secret'
SECRET_FILE_NAME = '/tmp/secret.json'
CURRNET_SECRET_OBJ = None
CURRNET_SECRET_OBJ_BACKUP = None
CHAIN_BASE_PATH = None

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

def run_cmd_until_ok(cmd, timeout=60):
    for i in range( int(timeout/5) ):
        rc, out = run_cmd(cmd)
        if rc != 0:
            time.sleep(5)
        else:
            return rc,out

def http_get(url):
    try:
        r = requests.get(url)
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
#         eprint(response)
#     return False


def get_current_secret_as_str():
    cmd = 'kubectl get secret {} -n {} -o json'.format(
        SECRET_NAME, CURRENT_NAMESPACE)
    rc, out = run_cmd(cmd)
    json_obj = convert_json_2_object(out)
    try:
        secret_base64 = json_obj['data'][os.path.basename(SECRET_FILE_NAME)]
        secret_str = convert_base64_2_str(secret_base64)
        return secret_str
    except:
        pass


def backup_current_secret():
    if not CURRNET_SECRET_OBJ_BACKUP:
        eprint('no secret at present!')
        return True

    current_secret = convert_object_2_json(CURRNET_SECRET_OBJ_BACKUP)

    with open(SECRET_FILE_NAME, 'w') as f:
        f.write(current_secret)
    backup_secret_name = SECRET_NAME + '-backup'

    cmd = 'kubectl delete secret --ignore-not-found=true {} -n {}'.format(
        backup_secret_name, CURRENT_NAMESPACE)
    rc, out = run_cmd(cmd)
    cmd = 'kubectl create secret generic {} --from-file={} -n {}'.format(
        backup_secret_name, SECRET_FILE_NAME, CURRENT_NAMESPACE)
    rc, out = run_cmd(cmd)
    return rc == 0


def create_update_operator_secret(session_key_json_obj):
    if backup_current_secret() == False:
        eprint('failed to backup current secret')
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
        eprint(traceback.format_exc())


def convert_object_2_json(python_object):
    try:
        return json.dumps(python_object)
    except Exception:
        eprint(traceback.format_exc())


def get_pod_ip_real(namespace, pod_name):
    cmd = 'kubectl get pod {} -n {} -o json'.format(pod_name, namespace)
    rc, out = run_cmd(cmd)
    if rc != 0:
        return None
    try:
        json_obj = convert_json_2_object(out)
        pod_ip = jmespath.search('status.podIP', json_obj)
        return pod_ip
    except Exception:
        eprint(traceback.format_exc())


def get_pod_ip(namespace, pod_name):
    for i in range(10):
        pod_ip = get_pod_ip_real(namespace, pod_name)
        if pod_ip:
            return pod_ip
        time.sleep(6)


def get_pod_restart_count(namespace, pod_name):
    cmd = 'kubectl get pod {} -n {} -o json'.format(pod_name, namespace)
    rc, out = run_cmd(cmd)
    try:
        json_obj = convert_json_2_object(out)
        restart_count = jmespath.search(
            'status.containerStatuses[0].restartCount', json_obj)
        if restart_count is None:
            return "-2"
        return restart_count
    except Exception:
        eprint(traceback.format_exc())
    return "-1"


def extract_pods_ips():
    for record in CURRNET_SECRET_OBJ:
        namespace = record['namespace']
        pod_name = record['pod_name']

        pod_ip = get_pod_ip(namespace, pod_name)
        record['pod_ip'] = pod_ip
        # record['restart_count'] = get_pod_restart_count(namespace, pod_name)
        # eprint(namespace, pod_name, pod_ip)


def get_max_best_finalized_number():
    best, finalized, sync_target = 0, 0, 0
    if CURRNET_SECRET_OBJ and len(CURRNET_SECRET_OBJ) > 0:
        for record in CURRNET_SECRET_OBJ:
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
    if CURRNET_SECRET_OBJ and len(CURRNET_SECRET_OBJ) > 0:
        for record in CURRNET_SECRET_OBJ:
            tmp_best = int(record.get('substrate_block_height_best', '-4'))
            tmp_finalized = int(record.get(
                'substrate_block_height_finalized', '-4'))
            # tmp_sync_target = int(record.get('substrate_block_height_sync_target', '-4'))
            if (best - tmp_best) > 6 or (finalized - tmp_finalized) > 6 or (sync_target - tmp_best) > 6:
                record['healthy'] = False
            else:
                record['healthy'] = True


def extract_pods_metrics():
    for record in CURRNET_SECRET_OBJ:
        namespace = record['namespace']
        pod_name = record['pod_name']
        pod_ip = record['pod_ip']
        record['substrate_block_height_best'] = '-5'
        record['substrate_block_height_finalized'] = '-5'
        record['substrate_block_height_sync_target'] = '-5'
        if not pod_ip:
            eprint(
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
            eprint(traceback.format_exc())


def show_data_frame():
    pd.set_option('display.max_rows', None)
    pd.set_option('display.max_columns', None)
    pd.set_option('display.width', None)
    df = pd.DataFrame(CURRNET_SECRET_OBJ, columns=[
                      'namespace', 'pod_name', 'pod_ip', 'substrate_block_height_best', 'substrate_block_height_finalized', 'substrate_block_height_sync_target', 'state', 'healthy', 'restart_count'])
    eprint(df)


# def get_public_key(cmd_out):
#     lines = cmd_out.split('\n')
#     for line in lines:
#         if 'Public key' in line:
#             line_seg_list = line.split(':')
#             if len(line_seg_list) == 2:
#                 return line_seg_list[-1].strip()
#
#     return None
#
#
# def get_public_key_sr25519(key_str):
#     cmd = 'subkey inspect "{}" --scheme=Sr25519'.format(key_str)
#     rc, out = run_cmd(cmd)
#     return get_public_key(out)


# def get_public_key_ed25519(key_str):
#     cmd = 'subkey inspect "{}" --scheme=Ed25519'.format(key_str)
#     rc, out = run_cmd(cmd)
#     return get_public_key(out)


def upload_subkey_to_pod(namespace, pod_name):
    cmd = 'kubectl -n {} exec {} -- ls -l /subkey'.format(namespace, pod_name)
    rc, out = run_cmd(cmd)
    if 'No such file or directory' in out or rc != 0:
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


def insert_keys(namespace, pod_name, node_session_key):
    rc = insert_key_type(namespace, pod_name, 'audi', node_session_key)
    rc = insert_key_type(namespace, pod_name, 'babe', node_session_key)
    rc = insert_key_type(namespace, pod_name, 'imon', node_session_key)
    rc = insert_key_type(namespace, pod_name, 'gran',
                         node_session_key, 'Ed25519')


def remove_session_keys(namespace, pod_name):
    cmd = 'kubectl exec -n {} {} -- /bin/bash -c \'rm -f {}/keystore/*\''.format(namespace, pod_name, CHAIN_BASE_PATH)
    return run_cmd_until_ok(cmd)

def kill_pod(namespace, pod_name):
    cmd = 'kubectl delete pod -n {} {}'.format(namespace, pod_name)
    rc, out = run_cmd(cmd)


def loop_work():
    global CURRNET_SECRET_OBJ
    global CURRNET_SECRET_OBJ_BACKUP

    secret_str = get_current_secret_as_str()
    CURRNET_SECRET_OBJ = convert_json_2_object(secret_str)
    CURRNET_SECRET_OBJ_BACKUP = convert_json_2_object(secret_str)

    if CURRNET_SECRET_OBJ and len(CURRNET_SECRET_OBJ) > 0:
        extract_pods_ips()
        extract_pods_metrics()
        best, finalized, sync_target = get_max_best_finalized_number()
        update_node_status(best, finalized, sync_target)
        show_data_frame()

        suspended_records = []
        idle_healthy_records = []

        for record in CURRNET_SECRET_OBJ:
            if record['state'] == 'suspension':
                suspended_records.append(record)
                continue
            namespace, pod_name = record['namespace'], record['pod_name']
            if record['state'] == 'staking' and record['healthy'] == False:
                eprint(
                    '{}/{} is unhealthy, need to remove the session key from it....'.format(namespace, pod_name))
                # if int(record.get('substrate_block_height_best', '-4')) <= 100:
                #     eprint('record might not be running properly, so we cannot properly remove the keys from it, skip it!!')
                #     eprint(record)
                #     continue
                
                rc, out = remove_session_keys(namespace, pod_name)
                if rc != 0:
                    eprint('failed to delete the keystore directory on pod {}/{}, skip swapping it'.format(namespace, pod_name))
                    continue
                time.sleep(5)
                
                eprint('need to kill the pod to force it to restart...')
                kill_pod(namespace, pod_name)
                # make sure there is no key files left

                record['state'] = 'suspension'
                suspended_records.append(record)
            elif record['state'] == 'idle' and record['healthy'] == True:
                idle_healthy_records.append(record)

        need_save_secret = False
        if len(suspended_records) > 0:
            need_save_secret = True

        for record in suspended_records:
            if len(idle_healthy_records) <=0:
                eprint('no healthy idle validator to swap to!!!')
                break
            
            healthy_record = idle_healthy_records.pop()
            if healthy_record:
                record['state'] = 'idle'
                healthy_record['state'] = 'staking'
                session_key = healthy_record['session_key'] = record['session_key']
                record['session_key'] = ""
                namespace, pod_name, pod_ip = healthy_record[
                    'namespace'], healthy_record['pod_name'], healthy_record['pod_ip'],
                insert_keys(namespace, pod_name, session_key)
                

        if need_save_secret:
            create_update_operator_secret(CURRNET_SECRET_OBJ)
    # reset secret obj
    CURRNET_SECRET_OBJ = None


_to_esc = re.compile(r'\s|[]()[]')
def _esc_char(match):
    return '\\' + match.group(0)

def my_escape(name):
    return _to_esc.sub(_esc_char, name)

def extract_chain_base_path():
    global CHAIN_BASE_PATH
    global CURRNET_SECRET_OBJ

    if CHAIN_BASE_PATH:
        return
    if CURRNET_SECRET_OBJ and len(CURRNET_SECRET_OBJ) > 0:
        for record in CURRNET_SECRET_OBJ:
            namespace, pod_name = record['namespace'], record['pod_name']
            cmd = 'kubectl -n {} exec {} -- ls /mnt/cennznet/chains/'.format(namespace, pod_name)
            rc, out = run_cmd(cmd)
            if rc != 0:
                eprint(out)
                continue
            base_path = os.path.join('/mnt/cennznet/chains/', out.strip())
            CHAIN_BASE_PATH = my_escape(base_path)
            if len(CHAIN_BASE_PATH) > 0:
                break


def main():
    try:
        start_http_server(8080)
        while True:
            now_dt = datetime.datetime.now()
            format = "%Y-%m-%d %H:%M:%S"
            eprint('-----------------{}------------------'.format(now_dt.strftime(format)))
            loop_work()
            time.sleep(60)
    except Exception:
        eprint(traceback.format_exc())


if __name__ == '__main__':
    CURRENT_NAMESPACE = get_namespace_for_current_pod()
    secret_str = get_current_secret_as_str()
    CURRNET_SECRET_OBJ = convert_json_2_object(secret_str)
    extract_chain_base_path()
    eprint(CURRNET_SECRET_OBJ)
    eprint(CHAIN_BASE_PATH)
    time.sleep(10)
    try:
        main()
    except Exception:
        eprint(traceback.format_exc())

