from strategy.DefenceStrategyBase import DefenceStrategyBase
import sys

class DefenceStrategyImplementation(DefenceStrategyBase):
    def __init__(self, dir):
        DefenceStrategyBase.__init__(self, dir)
        responses = []
        responses.append(Response('10.0.0.11', 'block'))
        responses.append(Response('10.0.0.12', 'block'))
        responses.append(Response('10.0.0.13', 'block'))
        responses.append(Response('10.0.0.14', 'block'))
        responses.append(Response('10.0.0.15', 'block'))
        responses.append(Response('10.0.0.11', 'allow'))
        responses.append(Response('10.0.0.12', 'allow'))
        responses.append(Response('10.0.0.13', 'allow'))
        responses.append(Response('10.0.0.14', 'allow'))
        responses.append(Response('10.0.0.15', 'allow'))
        self.responses = responses
    
    def defend(self, attacks):
        for attack in attacks:
            attacker = attack[0]
	    target = attack[1]
            state = self.get_firewall_state(attacker)
            best_cost = sys.maxint
            best_response = None
            for response in self.responses:
                cost = self.compute_cost(target, state, response)
                if cost < best_cost:
                    best_cost = cost
                    best_response = response

            if best_response.action == 'allow' and state[best_response.target] == 'blocked':
                self.unblock(attacker, best_response.target)
            if best_response.action == 'block' and state[best_response.target] == 'allowed':
                self.block(attacker, best_response.target)

	rules = self.get_all_active_blocks()
	for r in rules:
	    srcip = r[0].split('/')[0]
	    dstip = r[1].split('/')[0]
	    if not any(srcip == a[0] and dstip == a[1] for a in attacks):
		self.unblock(srcip, dstip)

    def compute_cost(self, target, state, response):
            cost = 0
            config = self.get_configuration()
            if (state[response.target] == 'allowed' and response.action == 'block') or (state[response.target] == 'blocked' and response.action == 'allow'):
                    cost += config["costs"]["reconfiguration"]
            if response.action == 'block':
                    cost += [x["value"] for x in config["costs"]["availability"] if x["ip"] == response.target][0]
            if response.action == 'block' and target == response.target:
                    cost -= config["success_probability"]*[x["value"] for x in config["costs"]["integrity"] if x["ip"] == response.target][0]
            return cost

class Response:
        def __init__(self, target, action):
                self.target = target
                self.action = action
