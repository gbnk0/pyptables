import os
import sys
import subprocess

default_binpath = "/sbin/iptables"

def rule_to_list(rule):
    listrule = []
    if rule.chain:
        listrule.append("-A")
        listrule.append(rule.chain.name)

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



def get_config(**kwargs):
    binpath = kwargs.get('binpath', default_binpath)
    output = subprocess.Popen([binpath+'-save'],
                          stdout=subprocess.PIPE).communicate()[0]
    return output


#USELESS
def clr(string, status):
    try:
        attr = []
        if status == 'G':
            attr.append('92')
        elif status == 'R':
            attr.append('91')
        elif status == 'B':
            attr.append('34')
        elif status == 'O':
            attr.append('93')
        attr.append('1')
        return '\x1b[%sm%s\x1b[0m' % (';'.join(attr), string)
    except:
        pass


def exec_cmd(cmd):
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE)
    result = p.communicate()[0].decode("utf-8")
    result = str(result)
    return result