from prometheus_client import start_http_server
import os, sys
import time
import subprocess
import json
import base64
import datetime

CURRENT_NAMESPACE = 'N/A'
SECRET_NAME = 'operator-secret'
SECRET_FILE_NAME = '/tmp/secret.json'

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

def run_cmd(cmd):
    eprint('CMD: ' + cmd)
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)
    result = process.communicate()[0]
    eprint('{},{}'.format(process.returncode, result.decode()))
    return process.returncode, result.decode()


def get_current_secret_as_str():
    cmd = 'kubectl get secret {} -n {} -o json'.format(SECRET_NAME, CURRENT_NAMESPACE)
    rc, out = run_cmd(cmd)
    json_obj = convert_json_2_object(out)
    try:
        secret = json_obj['data'][os.path.basename(SECRET_FILE_NAME)]
        return secret
    except:
        pass

def backup_current_secret():
    current_secret = get_current_secret_as_str()
    if not current_secret:
        eprint('no secret at present!')
        return True

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
    except:
        pass

def convert_object_2_json(python_object):
    try:
        return json.dumps(python_object)
    except:
        pass

def loop_work():
    secret_obj = [
        {'namespace': 'az-ie-cennznet-validators-blue',
        'pod_name': 'az-ie-cennznet-v-b-0', 
        'session_key': 'olympic vacant sight husband taste staff fragile actual region satoshi possible bronze clown address cotton silly detect private fit solar squeeze'},
        {'namespace': 'az-ie-cennznet-validators-blue',
        'pod_name': 'az-ie-cennznet-v-b-1', 
        'session_key': 'spawn devote citizen basic mountain humble title mutual beauty fringe blue oval decide confirm noodle duck famous chief edit ethics wonder'},
        {'namespace': 'az-ie-cennznet-validators-blue',
        'pod_name': 'az-ie-cennznet-v-b-2', 
        'session_key': 'wrist success tank profit jar strike ecology remain rare aware divorce album sentence ahead across alpha thunder cloth dinner rhythm seven'},
        {'namespace': 'az-ie-cennznet-validators-blue',
        'pod_name': 'az-ie-cennznet-v-b-3', 
        'session_key': 'buyer panther dumb suspect jaguar lunar what vintage sugar kangaroo security thumb apology consider column job never observe arena day fever'},

        {'namespace': 'az-ie-cennznet-validators-green',
        'pod_name': 'az-ie-cennznet-v-g-0', 
        'session_key': ''},
        {'namespace': 'az-ie-cennznet-validators-green',
        'pod_name': 'az-ie-cennznet-v-g-0', 
        'session_key': ''},
        {'namespace': 'az-ie-cennznet-validators-green',
        'pod_name': 'az-ie-cennznet-v-g-0', 
        'session_key': ''},
        {'namespace': 'az-ie-cennznet-validators-green',
        'pod_name': 'az-ie-cennznet-v-g-0', 
        'session_key': ''},
    ]
    create_update_operator_secret(secret_obj)

def main():
    start_http_server(8080)
    while True:
        loop_work()
        time.sleep(30)

if __name__ == '__main__':
    CURRENT_NAMESPACE = get_namespace_for_current_pod()
    main()
