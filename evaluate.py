import MySQLdb
import os.path
import json
from dateutil import parser
from datetime import datetime, timedelta

def evaluate_startegy(dir):
    config = json.loads(open('configuration.json', 'r').read())

    conn = MySQLdb.connect(host="localhost", user=config["db-username"], passwd=config["db-password"], db="cowrie")
    cur = conn.cursor()

    info = json.loads(open(os.path.join(dir, 'info'), 'r').read())
    experiment_start = parser.parse(info["start"])
    experiment_end = parser.parse(info["end"])

    action_logs = open(os.path.join(dir, 'log'), 'r').readlines()
    actions = []
    for a in action_logs:
        actions.append(json.loads(a))

    cur.execute("""SELECT sessions.ip FROM sessions INNER JOIN auth ON auth.session = sessions.id WHERE auth.timestamp >= '{}' AND auth.timestamp <= '{}' GROUP BY sessions.ip""".format(experiment_start, experiment_end))
    attackers = cur.fetchall()

    attacks = get_separate_attacks(attackers, config, experiment_start, experiment_end)

    results = []
    for attack in attacks:
        results.append(evaluate_attack(attack, actions, config, experiment_start, experiment_end))
    with open(os.path.join(dir, 'results'), 'w') as file:
        file.write(json.dumps(results))

def get_separate_attacks(attacks, config, experiment_start, experiment_end):
    conn = MySQLdb.connect(host="localhost", user=config["db-username"], passwd=config["db-password"], db="cowrie")
    cur = conn.cursor()

    separated_attacks = []
    #with open(path.join(dir, 'separate-attacks'), 'a') as file:
    for attack in attacks:
	attacker = attack[0]
	cur.execute("""SELECT auth.timestamp, sessions.ip AS rhost, sensors.ip AS host, auth.username, auth.password FROM sessions INNER JOIN auth ON auth.session = sessions.id INNER JOIN sensors ON sessions.sensor = sensors.id WHERE sessions.ip = '{}' AND auth.timestamp >= '{}' AND auth.timestamp <= '{}' ORDER BY timestamp""".format(attacker, experiment_start, experiment_end))
	attempts = cur.fetchall()
	
	if len(attempts) == 0:
		continue
	
	start = None
	previous = None

	sliding = []

	for row in attempts:
		time = row[0]

		if previous is None:
			previous = time
			start = time
			continue
		
		delta = time - previous

		if len(sliding) == 5:
			sliding.pop()
		sliding.append(delta)

		avg = sum(sliding, timedelta())/len(sliding)
		
		if delta.days > 0 or delta.seconds > 3600 or (delta.seconds > 300 and delta > avg*5):
			if (any(x[1] == row[1] and x[2] == row[2] and x[3] == row[3] and x[4] == row[4]) for x in attempts if (x[0] < time and x[0] >= start)):
                        	separated_attacks.append([attacker, str(start), str(previous)])
				start = time
				previous = time
				sliding = []
				continue

		previous = time

	separated_attacks.append([attacker, start, previous])
    return separated_attacks

def evaluate_attack(attack, actions, config, experiment_start, experiment_end):
	conn = MySQLdb.connect(host="localhost", user=config["db-username"], passwd=config["db-password"], db="cowrie")
    	cur = conn.cursor()

	penalty = 0
	start = attack[1]
	end = attack[2]
	attacker = attack[0]
		
	cur.execute("""SELECT sensors.ip AS host, auth.username, auth.password FROM sessions INNER JOIN auth ON auth.session = sessions.id INNER JOIN sensors ON sessions.sensor = sensors.id WHERE auth.timestamp >= '{}' AND auth.timestamp <= '{}' AND sessions.ip = '{}' GROUP BY host, username, password""".format(start, end, attacker))
	rows = cur.fetchall()

	#success penalty
	succeeded = []
	for t in config["honeypots"]:
		if any(r[0] == t["ip"] and r[1] == t["username"] and r[2] == t["password"] for r in rows):
			    cost = next(x for x in config["costs"]["integrity"] if x["ip"] == d[1])
			    penalty += cost["value"]
			    succeeded.append(t.ip)

	defence = [a for a in actions if a[0] == attacker and parser.parse(a[2]) >= start and parser.parse(a[2]) <= end]
        defence = sorted(defence, key = lambda z: z[3])

        for d in [d1 for d1 in defence if d1[2] == 'blocked' and not any(d1[0] == d2[0] and d1[1] == d2[1] and d2[2] == 'allowed' and d2[3] > d1[3] for d2 in defence)]:
                time =  parser.parse(d[3])
                unblock_action = next(a for a in actions if a[0] == d[0] and a[1] == d[1] and a[3] > d[3] and a[2] == 'allowed')
                defence.append(unblock_action)
        if any(a[0] == attacker and parser.parse(a[2]) > end and parser.parse(a[2]) <= experiment_end + timedelta(0, 60) and a[3] == 'blocked' for a in actions):
                block_actions = [a for a in actions if a[0] == attacker and a[3] >= end and a[3] <= str(experiment_end + timedelta(0, 60)) and a[2] == 'blocked']
                defence.extend(block_actions)
                for d in block_actions:
                        time =  parser.parse(d[3])(d[3])
                        unblock_action = next(a for a in actions if a[0] == d[0] and a[1] == d[1] and a[3] >= d[3] and a[2] == 'allowed')
                        defence.append(unblock_action)
	defence = sorted(defence, key = lambda z: z[2])

	if len(defence) == 0:
		return penalty
	
	#reconfiguration penalty
	penalty += 10*len(defence)
	print(defence)	
	#availability penalty
	blocked = [None, None, None, None, None, None]
	for d in defence:
		target = next(x for x in config["honeypots"] if x["ip"] == d[1])
		index = config["honeypots"].index(target)
		print(target)
		if d[3] == 'block' and blocked[index] is None:
			blocked[index] = parser.parse(d[2])
			print(blocked[index])
		if d[3] == 'allow' and not blocked[index] is None:
			delta = parser.parse(d[2]) - blocked[index]
			cost = next(x for x in config["costs"]["availability"] if x["ip"] == d[1])
			penalty += (delta.seconds/60)*cost["value"]
			blocked[index] = None
		
	return penalty
