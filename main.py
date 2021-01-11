from prometheus_client import start_http_server
import os, sys
import time
import subprocess
import json
import base64
import datetime
import traceback
import jmespath
import requests
import pandas as pd


CURRENT_NAMESPACE = 'N/A'
SECRET_NAME = 'operator-secret'
SECRET_FILE_NAME = '/tmp/secret.json'
CURRNET_SECRET_OBJ = None

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)
    sys.stderr.flush()

def run_cmd(cmd):
    eprint('CMD: ' + cmd)
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)
    result = process.communicate()[0]
    result_txt = result.decode()
    if process.returncode != 0:
        eprint('{},{}'.format(process.returncode, result_txt))
    return process.returncode, result_txt

def http_get(url):
    r = requests.get(url)
    return r.text

def get_current_secret_as_str():
    cmd = 'kubectl get secret {} -n {} -o json'.format(SECRET_NAME, CURRENT_NAMESPACE)
    rc, out = run_cmd(cmd)
    json_obj = convert_json_2_object(out)
    try:
        secret_base64 = json_obj['data'][os.path.basename(SECRET_FILE_NAME)]
        secret_str = convert_base64_2_str(secret_base64)
        return secret_str
    except:
        pass

def backup_current_secret():
    if not CURRNET_SECRET_OBJ:
        eprint('no secret at present!')
        return True

    current_secret = convert_object_2_json(CURRNET_SECRET_OBJ)

    with open(SECRET_FILE_NAME, 'w') as f:
        f.write(current_secret)
    now_dt = datetime.datetime.now()
    format = "%Y-%m-%d-%H%M"
    backup_secret_name = SECRET_NAME + '-backup'

    cmd = 'kubectl delete secret --ignore-not-found=true {} -n {}'.format(backup_secret_name, CURRENT_NAMESPACE)
    rc, out = run_cmd(cmd)
    cmd = 'kubectl create secret generic {} --from-file={} -n {}'.format(backup_secret_name, SECRET_FILE_NAME, CURRENT_NAMESPACE)
    rc, out = run_cmd(cmd)
    return rc == 0

def create_update_operator_secret(session_key_json_obj):
    if backup_current_secret() == False:
        eprint('failed to backup current secret')
        return False

    json_str = convert_object_2_json(session_key_json_obj)
    with open(SECRET_FILE_NAME, 'w') as f:
        f.write(json_str)

    cmd = 'kubectl delete secret --ignore-not-found=true {} -n {}'.format(SECRET_NAME, CURRENT_NAMESPACE)
    rc, out = run_cmd(cmd)

    cmd = 'kubectl create secret generic {} --from-file={} -n {}'.format(SECRET_NAME, SECRET_FILE_NAME, CURRENT_NAMESPACE)
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

def get_pod_ip(namespace, pod_name):
    cmd = 'kubectl get pod {} -n {} -o json'.format(pod_name, namespace)
    rc, out = run_cmd(cmd)
    try:
        json_obj = convert_json_2_object(out)
        pod_ip = jmespath.search('status.podIP', json_obj)
        return pod_ip
    except Exception:
        eprint(traceback.format_exc())

def get_pod_restart_count(namespace, pod_name):
    cmd = 'kubectl get pod {} -n {} -o json'.format(pod_name, namespace)
    rc, out = run_cmd(cmd)
    try:
        json_obj = convert_json_2_object(out)
        restart_count = jmespath.search('status.containerStatuses[0].restartCount', json_obj)
        return restart_count
    except Exception:
        eprint(traceback.format_exc())

def extract_pods_ips():
    for record in CURRNET_SECRET_OBJ:
        namespace = record['namespace']
        pod_name = record['pod_name']
        
        pod_ip = get_pod_ip(namespace, pod_name)
        record['pod_ip'] = pod_ip
        record['restart_count'] = get_pod_restart_count(namespace, pod_name)
        eprint(namespace, pod_name, pod_ip)

def get_max_best_finalized_number():
    best, finalized = 0, 0
    if CURRNET_SECRET_OBJ and len(CURRNET_SECRET_OBJ) > 0:
        for record in CURRNET_SECRET_OBJ:
            tmp_best = int(record['substrate_block_height_best'])
            tmp_finalized = int(record['substrate_block_height_finalized'])
            if tmp_best > best:
                best = tmp_best
            if tmp_finalized > finalized:
                finalized = tmp_finalized

    return best, finalized


def update_node_status(best, finalized):
    if CURRNET_SECRET_OBJ and len(CURRNET_SECRET_OBJ) > 0:
        for record in CURRNET_SECRET_OBJ:
            tmp_best = int(record['substrate_block_height_best'])
            tmp_finalized = int(record['substrate_block_height_finalized'])
            if (best - tmp_best) > 6 or (finalized - tmp_finalized) > 6:
                record['healthy'] = False
            else:
                record['healthy'] = True

def extract_pods_metrics():
    for record in CURRNET_SECRET_OBJ:
        namespace = record['namespace']
        pod_name = record['pod_name']
        pod_ip = record['pod_ip']
        if not pod_ip:
            eprint('{}/{} pod ip {}, cannot extract metrics'.format(namespace, pod_name, pod_ip))
            record['substrate_block_height_best'] = 0
            record['substrate_block_height_finalized'] = 0
            record['substrate_block_height_sync_target'] = 0
            return
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
            record['substrate_block_height_best'] = 0
            record['substrate_block_height_finalized'] = 0
            record['substrate_block_height_sync_target'] = 0


def show_data_frame():
    pd.set_option('display.max_rows', None)
    pd.set_option('display.max_columns', None)
    pd.set_option('display.width', None)
    df = pd.DataFrame(CURRNET_SECRET_OBJ, columns=['namespace', 'pod_name', 'pod_ip', 'substrate_block_height_best', 'substrate_block_height_finalized','healthy', 'restart_count'])
    eprint(df)


def loop_work():
    global CURRNET_SECRET_OBJ
    secret_str = get_current_secret_as_str()
    CURRNET_SECRET_OBJ = convert_json_2_object(secret_str)
    if CURRNET_SECRET_OBJ and len(CURRNET_SECRET_OBJ) > 0:
        extract_pods_ips()
        extract_pods_metrics()
        best, finalized = get_max_best_finalized_number()
        update_node_status(best, finalized)
        show_data_frame()

        create_update_operator_secret(CURRNET_SECRET_OBJ)
    # reset secret obj 
    CURRNET_SECRET_OBJ = None

def main():
    try:
        start_http_server(8080)
        while True:
            loop_work()
            time.sleep(60)
    except Exception:
        eprint(traceback.format_exc())
    

if __name__ == '__main__':
    CURRENT_NAMESPACE = get_namespace_for_current_pod()
    main()
