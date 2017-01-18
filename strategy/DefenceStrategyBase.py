import os
from datetime import datetime
import iptc
import path
import json

class DefenceStrategyBase:
    def __init__(self, dir):
        self.configuration = json.loads(open('configuration.json', 'r').read())
        self.dir = dir
    
    def get_configuration(self):
        return self.configuration
    
    def get_firewall_state(self, srcip):
        state = {}
        chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
        for target in self.configuration.honeypots:
                if any(srcip in r.src and target.ip in r.dst for r in chain.rules):
                        state[target.ip] = 'blocked'
                else:
                        state[target.ip] = 'allowed'
        return state

    def unblock(self, srcip, dstip):
        rule = iptc.Rule()
        rule.src = srcip
        rule.dst = dstip
        rule.target = iptc.Target(rule, "DROP")
        chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
        chain.delete_rule(rule)
        with open(path.join(self.dir, 'log'), 'a') as log:
            log.write(json.dumps([srcip, dstip, datetime.utcnow().isoformat(), "allow"]))


    def block(self, srcip, dstip):
        rule = iptc.Rule()
        rule.src = srcip
        rule.dst = dstip
        rule.target = iptc.Target(rule, "DROP")
        chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
        chain.insert_rule(rule)
        with open(path.join(self.dir, 'log'), 'a') as log:
            log.write(json.dumps([srcip, dstip, datetime.utcnow().isoformat(), "block"]))

   