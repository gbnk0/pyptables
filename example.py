from pyptables import Pyptables, utils

if __name__ == '__main__':
    iptables = Pyptables.Iptables()
    # r.dst = '172.2.1.2/32'
    rule = Pyptables.Rule(action='ACCEPT', src='192.168.0.0/24', chain='FORWARD', dports=[80,443], proto='tcp', comment='Web_Administration', in_if='eth0', out_if='eth0')
    iptables.add(rule)
    iptables.commit()

    # # Get rules


    c = Pyptables.Chain(name='INPUT')
    print(c.rules)
    for r in c.rules:
        print(Pyptables.rule_to_list(r))