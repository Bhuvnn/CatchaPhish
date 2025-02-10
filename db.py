from cassandra.cluster import Cluster
from cassandra.auth import PlainTextAuthProvider
import os
import uuid
from datetime import datetime

cloud_config= {
  'secure_connect_bundle': r'secure-connect-phishing-db.zip'
}
CLIENT_ID = os.environ.get["clientId"]
CLIENT_SECRET = os.environ.get["secret"]

auth_provider = PlainTextAuthProvider(CLIENT_ID, CLIENT_SECRET)
cluster = Cluster(cloud=cloud_config, auth_provider=auth_provider)
session = cluster.connect()

session.set_keyspace("phishing_data")





