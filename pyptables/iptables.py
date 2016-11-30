import os
import sys
import subprocess
from utils import rule_to_list

default_binpath = "/sbin/iptables"


class Iptables:

    def __init__(self, **kwargs):
        self.binpath = kwargs.get('binpath', default_binpath)
        self.rules = []
        self.chains = self.get_chains()

    def add(self, rule):
        self.rules.append(rule)
        return self.rules

    def commit(self):
        for r in self.rules:
            curule = [self.binpath]
            for i in r.get():
                curule.append(i)

            subprocess.call(curule)

        return True

    def get_chains(self):
        chains = []
        output = subprocess.Popen(
                            [self.binpath, "-vnL"], stdout=subprocess.PIPE
                                  ).communicate()[0]
        for line in output.splitlines():
            if line.startswith('Chain'):
                c = Chain(name=line.split()[1])
                chains.append(c)
        return chains


class Rule:

    def __init__(self, **kwargs):
        self.action = kwargs.get('action', 'ACCEPT')
        self.chain = kwargs.get('chain', 'INPUT')
        self.comment = kwargs.get('comment', '')
        self.match = kwargs.get('match', '')
        self.dports = kwargs.get('dports', [])
        self.src = kwargs.get('src', '')
        self.dst = kwargs.get('dst', '')
        self.proto = kwargs.get('proto', '')
        self.in_if = kwargs.get('in_if', '')
        self.out_if = kwargs.get('out_if', '')

    def get(self):
        return rule_to_list(self)


class Chain:

    def __init__(self, **kwargs):
        self.binpath = kwargs.get('binpath', default_binpath)
        self.name = kwargs.get('name', '')
        self.rules = self.get_rules()

    def get_rules(self):
            try:
                rules = []
                output = subprocess.Popen(
                                            [self.binpath, "-vnL", self.name],
                                            stdout=subprocess.PIPE
                                          ).communicate()[0]

                for line in output.splitlines():
                    line = line.strip()

                    if not line.startswith('Chain'):
                        if not line.startswith('pkts'):

                            rule = Rule(chain=self.name,
                                        action=line.split()[2],
                                        proto=line.split()[3])

                            linesplit = line.split()
                            print(len(linesplit), linesplit)
                            in_if = linesplit[5]
                            out_if = linesplit[6]
                            src = linesplit[7]
                            dst = linesplit[8]

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

                            rules.append(rule)

                return rules
            except:
                print('debug:', line)
                raise
