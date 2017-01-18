import DefenceStrategyImplementation
import psycopg2

dir = sys.argv[1]
configuration = json.loads(open('configuration.json', 'r').read())

#retrieve detected attacks
conn = psycopg2.connect(configuration.db)
cur = conn.cursor()
cur.execute("""SELECT rhost, host FROM passwords WHERE timestamp > now() -  time '00:01' AND host <<= 'x.x.x.1/29' GROUP BY rhost, host""")
rows = cur.fetchall()

#run strategy logic
strategy = DefenceStrategyImplementation(dir)
strategy.defend(rows)