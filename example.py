import pyptables

if __name__ == '__main__':
    
    """ Create a new iptables object """
    iptables = pyptables.Iptables()
    iptables.show()

    """ Or with custom path"""
    # iptables = pyptables.Iptables(binpath='/sbin/iptables')

    """ Create a new rule """
    rule = pyptables.Rule(
                          action='ACCEPT',
                          src='192.168.0.0/24',
                          chain='FORWARD',
                          dports=[80,443],
                          proto='tcp',
                          comment='Web_Administration',
                          in_if='eth0',
                          out_if='eth0'
                          )
    """ Or """
    # rule = pyptables.Rule()
    # rule.action='ACCEPT'
    # rule.src='192.168.0.0/24'
    # rule.chain='FORWARD'
    # rule.dports=[80,443]
    # rule.proto='tcp'
    # rule.comment='Web_Administration'
    # rule.in_if='eth0'
    # rule.out_if='eth0'

    """ Ad the rule to iptables """
    iptables.add(rule)

    """ Commit the changes """
    iptables.commit() # Uncomment for commit changes to your curent system

    """ Get rules in chain """
    # input_chain = pyptables.Chain(name='INPUT')
    # print(input_chain.rules) # Returns a list of rule objects

    # Test
    # for r in input_chain.rules:
    #     print(r.hits, r.action, r.chain.name, r.proto, r.dports, r.in_if, r.out_if, r.src, r.dst)

    iptables.optimize()