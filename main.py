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
CURRNET_SECRET_OBJ_BACKUP = None
CHAIN_NAME = 'Azalea'

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

def http_post(http_url, post_json_body):
    json_obj = convert_json_2_object(post_json_body)
    response = requests.post(http_url, json=json_obj, headers={'Content-Type': 'application/json'})
    if response.status_code == 200:
        return True
    else:
        eprint(response)
    return False

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
    if not CURRNET_SECRET_OBJ_BACKUP:
        eprint('no secret at present!')
        return True

    current_secret = convert_object_2_json(CURRNET_SECRET_OBJ_BACKUP)

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
    df = pd.DataFrame(CURRNET_SECRET_OBJ, columns=['namespace', 'pod_name', 'pod_ip', 'substrate_block_height_best', 'substrate_block_height_finalized', 'state', 'healthy', 'restart_count'])
    eprint(df)

def get_public_key(cmd_out):
    lines = cmd_out.split('\n')
    for line in lines:
        if 'Public key' in line:
            line_seg_list = line.split(':')
            if len(line_seg_list) == 2:
                return line_seg_list[-1].strip()

    return None

def get_public_key_sr25519(key_str):
    cmd = 'subkey inspect "{}" --scheme=Sr25519'
    rc, out = run_cmd(cmd)
    return get_public_key(out)

def get_public_key_ed25519(key_str):
    cmd = 'subkey inspect "{}" --scheme=Ed25519'
    rc, out = run_cmd(cmd)
    return get_public_key(out)

def insert_key_gran(node_ip, key_type, node_session_key):
    gran_request = '''
    {
    "jsonrpc": "2.0",
    "method": "author_insertKey",
    "params": [
      "{}",
      "{}",
      "{}"
    ],
    "id": 0
    }
    '''
    post_json_body = gran_request.format(node_session_key, key_type, node_session_key)
    http_url = 'http://{}:9933'.format(node_ip)
    return http_post(http_url, post_json_body)

def insert_keys(node_ip, node_session_key):
    key_sr25519 = get_public_key_sr25519(node_session_key)
    key_ed25519 = get_public_key_ed25519(node_session_key)
    rc = insert_key_gran(node_ip, 'audi', key_sr25519)
    rc = insert_key_gran(node_ip, 'babe', key_sr25519)
    rc = insert_key_gran(node_ip, 'imon', key_sr25519)
    rc = insert_key_gran(node_ip, 'gran', key_ed25519)

def remove_session_keys(namespace, pod_name):
    cmd = 'kubectl exec -n {} {} -- ls /mnt/cennznet/chains/CENNZnet\ {}\ V1/keystore/'.format(namespace, pod_name, CHAIN_NAME)
    rc, out = run_cmd(cmd)
    lines = out.strip().split('\n')
    for line in lines:
        if len(line.strip()) <= 0:
            continue 
        cmd = 'kubectl exec -n {} {} -- rm -f /mnt/cennznet/chains/CENNZnet\ {}\ V1/keystore/{}'.format(namespace, pod_name, CHAIN_NAME,
                                                                                                line.strip())
        rc, out = run_cmd(cmd)

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
        best, finalized = get_max_best_finalized_number()
        update_node_status(best, finalized)
        show_data_frame()

        suspended_records = []
        idle_healthy_records = []

        for record in CURRNET_SECRET_OBJ:
            namespace, pod_name = record['namespace'], record['pod_name']
            if record['state'] == 'staking' and record['healthy'] == False:
                eprint('{}/{} is unhealthy, need to remove the session key from it....')
                remove_session_keys(namespace, pod_name)
                time.sleep(5)
                current_restart_count = int(record['restart_count'])
                new_restart_count = int(get_pod_restart_count(namespace, pod_name) )
                eprint('current_restart_count {}, new_restart_count {}'.format(current_restart_count, new_restart_count))
                if new_restart_count <= current_restart_count:
                    eprint('need to kill the pod to force it to restart...')
                    kill_pod(namespace, pod_name)
                    new_restart_count = int(get_pod_restart_count(namespace, pod_name) )
                    record['restart_count'] = new_restart_count
                record['state'] == 'suspension'
                suspended_records.append(record)
            elif record['state'] == 'idle' and record['healthy'] == True:
                idle_healthy_records.append(record)
        
        need_save_secret = False

        for record in suspended_records:
            healthy_record = idle_healthy_records.pop()
            if healthy_record:
                record['state'] = 'idle'
                healthy_record['state'] = 'staking'
                session_key = healthy_record['session_key'] = record['session_key']
                record['session_key'] = ""
                namespace, pod_name, pod_ip = healthy_record['namespace'], healthy_record['pod_name'], healthy_record['pod_ip'], 
                insert_keys(pod_ip, session_key)
                need_save_secret = True

        if need_save_secret:
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
