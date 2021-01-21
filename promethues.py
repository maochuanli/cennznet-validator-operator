import random
import prometheus_client
from prometheus_client import Histogram
from flask import Response, Flask


app = Flask(__name__)
h  = Histogram("h1", 'A Histogram', buckets=(-5, 0, 5))
@app.route("/")
def r_value():
    h.observe(random.randint(-5, 5))
    return Response('observe ....',
                    mimetype="text/plain")

@app.route("/metrics/")
def r_value2():
    return Response(prometheus_client.generate_latest(),
                    mimetype="text/plain")

if __name__ == "__main__":
  app.run(host="127.0.0.1",port=8081)