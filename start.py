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
copyfile(logic_implementation, os.path.join('strategy', 'DefenceStrategyImplementation.py'))
copyfile(logic_implementation, path)

#create Cron job
cron = CronTab(user=True, comment='strategy evaluation')
command = 'python {0}/respond.py {1}'.format(os.path.abspath(), path)
job  = cron.new(command=command)
job.minute.every(1)
job.enable()

#note beginning
with open(path.join(path, 'info'), 'w+') as info:
    info.write(json.dumps({start: datetime.now().isoformat()}))