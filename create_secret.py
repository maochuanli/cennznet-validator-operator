import json
import base64

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
    'pod_name': 'az-ie-cennznet-v-g-1', 
    'session_key': ''},
    {'namespace': 'az-ie-cennznet-validators-green',
    'pod_name': 'az-ie-cennznet-v-g-2', 
    'session_key': ''},
    {'namespace': 'az-ie-cennznet-validators-green',
    'pod_name': 'az-ie-cennznet-v-g-3', 
    'session_key': ''},
]

# secret_json = json.dumps(secret_obj)
# print(secret_json)

# message_bytes = secret_json.encode('ascii')
# base64_bytes = base64.b64encode(message_bytes)
# base64_message = base64_bytes.decode('ascii')

# print(base64_message)

# base64_bytes = base64_message.encode('ascii')
# message_bytes = base64.b64decode(base64_bytes)
# message = message_bytes.decode('ascii')

# print(message)

for record in secret_obj:
    print(type(record))
    print(record.get('xxx', 'xx'))