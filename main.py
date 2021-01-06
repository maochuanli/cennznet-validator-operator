from prometheus_client import start_http_server
import time

start_http_server(8080)

while True:
    time.sleep(5)