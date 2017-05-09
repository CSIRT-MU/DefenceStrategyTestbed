from strategy.DefenceStrategyImplementation import DefenceStrategyImplementation
from datetime import datetime
import MySQLdb
import os.path
import sys
import json

dir = sys.argv[1]
base_path = os.path.dirname(os.path.realpath(__file__))
config_path = os.path.join(base_path, "configuration.json")
configuration = json.loads(open(config_path, 'r').read())

with open(os.path.join(dir, 'debug'), 'a') as log:
        log.write("Run started at {}\n".format(datetime.utcnow()))

#retrieve detected attacks
db = MySQLdb.connect(host="localhost", user=configuration["db-username"], passwd=configuration["db-password"], db="cowrie")
cur = db.cursor()
cur.execute("""SELECT sessions.ip AS rhost, sensors.ip AS host FROM sessions INNER JOIN auth ON auth.session = sessions.id INNER JOIN sensors ON sessions.sensor = sensors.id WHERE auth.timestamp > DATE_SUB(UTC_TIMESTAMP(), INTERVAL 1 MINUTE) GROUP BY rhost, host""")
rows = cur.fetchall()

print(rows)

#run strategy logic
strategy = DefenceStrategyImplementation(dir)
strategy.defend(rows)

with open(os.path.join(dir, 'debug'), 'a') as log:
	log.write("Run ok at {}\n".format(datetime.utcnow()))
