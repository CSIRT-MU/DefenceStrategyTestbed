import sys
from datetime import datetime
import os
import json
import shutil
from crontab import CronTab

logic_implementation = sys.argv[1]

#create folder
path = os.path.join('logs', datetime.now().strftime('%Y-%m-%dT%H-%M'))
if not os.path.exists(path):
    os.makedirs(path)

#copy and rename logic implementation
shutil.copyfile(logic_implementation, os.path.join('strategy', 'DefenceStrategyImplementation.py'))
shutil.copyfile(logic_implementation, os.path.join(path, 'DefenceStrategyImplementation.py'))

#create Cron job
cron = CronTab(user=True)
command = 'python {0}/respond.py {1}/{2} >> {3}/debug 2>&1'.format(os.path.dirname(os.path.realpath(__file__)), os.path.dirname(os.path.realpath(__file__)), path, os.path.dirname(os.path.realpath(__file__)))
job  = cron.new(command=command, comment='strategy evaluation')
job.minute.every(1)
job.enable()
cron.write_to_user(user=True)

#note beginning
with open(os.path.join(path, 'info'), 'w+') as info:
    info.write(json.dumps({"start": datetime.utcnow().isoformat()}))
