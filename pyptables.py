import os
import sys
import subprocess


default_binpath = "/sbin/iptables"

def rule_to_list(rule):
    listrule = []
    if rule.chain:
        listrule.append("-A")
        listrule.append(rule.chain)

    if rule.in_if:
        listrule.append("-i")
        listrule.append(rule.in_if)
    
    if rule.out_if:
        listrule.append("-o")
        listrule.append(rule.out_if)
    
    if rule.src:
        listrule.append("-s")
        listrule.append(rule.src)

    if rule.dst:
        listrule.append("-d")
        listrule.append(rule.dst)

    if rule.proto:
        listrule.append("-p")
        listrule.append(rule.proto)

    if len(rule.dports) > 0:
        listrule.append("-m")
        listrule.append("multiport")
        listrule.append("--dports")
        dports = ""
        for p in rule.dports:
            dports += str(p) + ','
        dports = dports[:-1]
        listrule.append(dports)

    if len(rule.comment) > 0:
        listrule.append("-m")
        listrule.append("comment")
        listrule.append("--comment")
        listrule.append(rule.comment)

    if len(rule.action) > 0:
        listrule.append("-j")
        listrule.append(rule.action)      
    
    return listrule

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
        output = subprocess.Popen([self.binpath, "-vnL"], stdout=subprocess.PIPE).communicate()[0]
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
                output = subprocess.Popen([self.binpath, "-vnL", self.name],
                                          stdout=subprocess.PIPE).communicate()[0]

                for line in output.splitlines():
                    line = line.strip()

                    if not line.startswith('Chain'):
                        if not line.startswith('pkts'):

                            rule = Rule(chain=self.name,
                                        action=line.split()[2],
                                        proto=line.split()[3])

                            linesplit = line.split()
                            in_if = linesplit[5]
                            out_if = linesplit[6]
                            src = linesplit[7]
                            dst = linesplit[8]

                            if len(linesplit) >= 11:
                                if 'multiport' in linesplit:
                                    dports = linesplit[11]
                                    dports = dports.split(',')
                                    rule.dports = dports
                            
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
                print(line)
                raise


if __name__ == '__main__':
    # iptables = Iptables()

    # r = Rule(action='DROP', src='192.168.0.0/24', chain='FORWARD', dports=[80,443], proto='tcp', comment='Administration-web', in_if='eth0', out_if='eth0')
    # r.dst = '172.2.1.2/32'
    
    # iptables.add(r)
    # iptables.commit()

    # # Get rules


    c = Chain(name='INPUT')
    print(c.rules)
    for r in c.rules:
        print(rule_to_list(r))
