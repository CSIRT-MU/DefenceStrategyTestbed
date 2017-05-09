import os
from datetime import datetime
import iptc
import os.path
import os
import json

class DefenceStrategyBase:
    def __init__(self, dir):
	base_path = os.path.join(dir, os.pardir, os.pardir)
	self.configuration = json.loads(open(os.path.join(base_path, 'configuration.json'), 'r').read())
        self.dir = dir
    
    def get_configuration(self):
        return self.configuration
    
    def get_firewall_state(self, srcip):
        state = {}
        chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
        for target in self.configuration["honeypots"]:
                if any(srcip in r.src and target["ip"] in r.dst for r in chain.rules):
                        state[target["ip"]] = 'blocked'
                else:
                        state[target["ip"]] = 'allowed'
        return state
	 
    def get_all_active_blocks(self):
       	chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
       	honeypots = [h["ip"] for h in self.configuration["honeypots"]]
        rules = [[r.src, r.dst] for r in chain.rules if any(r.dst.startswith(h) for h in honeypots)]
     	return rules


    def unblock(self, srcip, dstip):
        rule = iptc.Rule()
        rule.src = srcip
        rule.dst = dstip
        rule.target = iptc.Target(rule, "DROP")
        chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
        chain.delete_rule(rule)
        with open(os.path.join(self.dir, 'log'), 'a') as log:
            log.write(json.dumps([srcip, dstip, datetime.utcnow().isoformat(), "allow"]) + '\n')


    def block(self, srcip, dstip):
        rule = iptc.Rule()
        rule.src = srcip
        rule.dst = dstip
        rule.target = iptc.Target(rule, "DROP")
        chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
        chain.insert_rule(rule)
        with open(os.path.join(self.dir, 'log'), 'a') as log:
            log.write(json.dumps([srcip, dstip, datetime.utcnow().isoformat(), "block"]) + '\n')

   
