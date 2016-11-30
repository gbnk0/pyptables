
import os
import sys
import subprocess
from .utils import rule_to_list, default_binpath, get_config, clr, exec_cmd


class Iptables:

    def __init__(self, **kwargs):
        self.binpath = kwargs.get('binpath', default_binpath)
        self.rules = []
        self.chains = get_chains(self.binpath)

    def add(self, obj):
        self.rules.append(obj)
        return self.rules
    
    def commit(self):
        for r in self.rules:
            curule = [self.binpath]
            for i in r.get():
                curule.append(i)

            exec_cmd(curule)

        return True

    def show(self):
        return get_config(binpath=self.binpath)

    def optimize(self):
        for c in self.chains:
            for r in c.rules:
                # Must be int later
                if r.hits == '0':
                    txt = "[{}] You can remove this rule: ".format(clr('*', 'G'))
                    print(txt, r.get())
class Rule:

    def __init__(self, **kwargs):
        self.action = kwargs.get('action', 'ACCEPT')
        self.chain = Chain(name=kwargs.get('chain', 'INPUT'))
        self.comment = kwargs.get('comment', '')
        self.match = kwargs.get('match', '')
        self.dports = kwargs.get('dports', [])
        self.src = kwargs.get('src', '')
        self.dst = kwargs.get('dst', '')
        self.proto = kwargs.get('proto', '')
        self.in_if = kwargs.get('in_if', '')
        self.out_if = kwargs.get('out_if', '')
        self.hits = 0

    def get(self):
        return rule_to_list(self)



class Chain:

    def __init__(self, **kwargs):
        self.binpath = kwargs.get('binpath', default_binpath)
        self.name = kwargs.get('name', '')
        self.rules = get_rules(self.binpath, self.name)


""" Rules functions """

def get_rules(binpath, chain_name):
        try:
            rules = []
            output = exec_cmd([binpath, "-vnL", chain_name])

            for line in output.splitlines():
                line = line.strip()

                if not line.startswith("Chain"):
                    if not line.startswith('pkts'):

                        linesplit = line.split()

                        if len(linesplit) > 0:
                            hits = linesplit[1]
                            action= line.split()[2]
                            in_if = linesplit[5]
                            out_if = linesplit[6]
                            src = linesplit[7]
                            dst = linesplit[8]
                            proto = line.split()[3]

                            rule = Rule(chain=chain_name,
                                        action=action,
                                        proto = proto
                                        )
                            
                            if len(linesplit) >= 11:
                                if 'multiport' in linesplit:
                                    dports = linesplit[11]
                                    dports = dports.split(',')
                                    rule.dports = dports

                                if any('dpt:' in term for term in linesplit):
                                    port = linesplit[10]
                                    port = port.split(':')[1]
                                    rule.dports = [port]


                            if in_if != '*':
                                rule.in_if = in_if

                            if out_if != '*':
                                rule.out_if = out_if

                            if src != '0.0.0.0/0':
                                rule.src = src     

                            if dst != '0.0.0.0/0':
                                rule.dst = dst

                            rule.hits = hits


                            rules.append(rule)

            for r in rules:
                yield r
        except:
            print('####DEBUG####:', linesplit)
            raise

""" Chains functions """
def get_chains(binpath):
    chains = []
    output = exec_cmd([binpath, "-vnL"])
    for line in output:
        line = line.split()
        if len(line) > 0:
            if line[0] == 'Chain':
                c = Chain(name=line.split()[1])
                chains.append(c)
    return chains

