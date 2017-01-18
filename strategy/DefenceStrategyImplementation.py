import DefenceStrategyBase
import sys

class DefenceStrategyImplementation(DefenceStrategyBase):
    def __init__(self, dir):
        DefenceStrategyBase.__init__(self, dir)
        responses = []
        responses.append(Response('x.x.x.2', 'block'))
        responses.append(Response('x.x.x.3', 'block'))
        responses.append(Response('x.x.x.4', 'block'))
        responses.append(Response('x.x.x.5', 'block'))
        responses.append(Response('x.x.x.6', 'block'))
        responses.append(Response('x.x.x.2', 'allow'))
        responses.append(Response('x.x.x.3', 'allow'))
        responses.append(Response('x.x.x.4', 'allow'))
        responses.append(Response('x.x.x.5', 'allow'))
        responses.append(Response('x.x.x.6', 'allow'))
        self.responses = responses
    
    def defend(self, attacks):
        for attack in attacks:
            attacker = attack[0]
            state = self.get_firewall_state(attacker)
            best_cost = sys.maxint
            best_response = None
            for response in responses:
                cost = compute_cost(target, state, response)
                if cost < min_cost:
                    best_cost = cost
                    best_response = response

            if best_response.action == 'allow' and state[best_response.target] == 'blocked':
                self.unblock(attacker, best_response.target)
            if best_response.action == 'block' and state[best_response.target] == 'allowed':
                self.block(attacker, best_response.target)

    def compute_cost(target, state, response):
            cost = 0
            config = self.get_configuration()
            if (state[response.target] == 'allowed' and response.action == 'block') or (state[response.target] == 'blocked' and response.action == 'allow'):
                    cost += config.costs.reconfiguration
            if response.action == 'block':
                    cost += [x.value for x in config.costs.availability if x.ip == response.target][0]
            if response.action == 'block' and target == response.target:
                    cost -= config.success_probability*[x.value for x in config.costs.integrity if x.ip == response.target][0]
            return cost

class Response:
        def __init__(self, target, action):
                self.target = target
                self.action = action
