import evaluate
from datetime import datetime

dirs = sorted(os.walk('logs'), key = lambda z: z[0])
dir = dirs[0]

#remove cron job
cron = CronTab(user=True)
job = cron.find_comment('strategy evaluation')
cron.remove(job)

#note end
info = json.loads(open(path.join(dir, 'info.json'), 'r').read())
info.end = datetime.now().isoformat()
with open(path.join(path, 'info'), 'w') as file:
    file.write(json.dumps(info))

#prepare logs fo evaluation

#run evaluation
evaluate.evaluate_startegy(dir)