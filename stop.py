import evaluate
import json
import os.path
from crontab import CronTab
from datetime import datetime


dirs = sorted([name for name in os.listdir('logs') if os.path.isdir(os.path.join('logs', name))], reverse=True)
dir = dirs[0]

#remove cron job
cron = CronTab(user=True)
cron.remove_all(comment="strategy evaluation")
cron.write()

#note end
info_file = os.path.join('logs', dir, 'info')
info = json.loads(open(info_file, 'r').read())
info["end"] = datetime.utcnow().isoformat()
with open(info_file, 'w') as file:
    file.write(json.dumps(info))

#prepare logs fo evaluation

#run evaluation
evaluate.evaluate_startegy(os.path.join('logs', dir))
