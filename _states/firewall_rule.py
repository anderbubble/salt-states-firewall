'''
Management of firewall rules
============================

This is one of a set of generic firewall modules.  This module
specifically is designed to manage firewall rules.

.. code-block:: yaml

    httpd:
      firewall.managed:
        - table: filter
        - chain: INPUT
        - jump: ACCEPT
        - match: state
        - connstate: NEW
        - dport: 80
        - proto: tcp
        - sport: 1025:65535

'''


def managed (
        name,
        table='filter',
        chain='INPUT',
        action=None,
        in_interface=None,
        state_=None,
        reject_with=None,
        protocol=None,
        dports=None,
        ports=None,
):
    '''
    Manage a rule in the firewall

    name
        A user-defined name to call this rule by in another part of a state or
        formula. This should not be an actual rule.

    All other arguments are passed in with the same name as the long option
    that would normally be used for iptables, with one exception: `--state` is
    specified as `connstate` instead of `state` (not to be confused with
    `ctstate`).
    '''
    ret = {'name': name,
           'changes': {},
           'result': None,
           'comment': ''}

    args = []
    args.extend(_process_arg('-p', protocol))
    if set([dports, ports]) != set([None]):
        args.extend(_process_arg('-m', 'multiport'))
        if ports is not None:
            if isinstance(ports, (basestring, int)):
                value = str(ports)
            else:
                value = ','.join(ports)
            args.extend(_process_arg('--ports', value))
        if dports is not None:
            if isinstance(dports, (basestring, int)):
                value = str(dports)
            else:
                value = ','.join(dports)
            args.extend(_process_arg('--dports', value))
    args.extend(_process_arg('-m', 'comment'))
    args.extend(_process_arg('--comment', name))
    args.extend(_process_arg('--in-interface', in_interface))
    if state_ is not None:
        args.extend(_process_arg('-m', 'state'))
        if isinstance(state_, basestring):
            value = state_
        else:
            value = ','.join(state_)
        args.extend(_process_arg('--state', value))
    args.extend(_process_arg('-j', action.upper()))
    args.extend(_process_arg('--reject-with', reject_with))

    rule = ' '.join(args)
    rulenum = _get_rulenum(table, chain, name)

    if __salt__['iptables.check'](table, chain, rule) is True:
        ret['result'] = True
        ret['comment'] = 'iptables rule for {0!r} already set ({1})'.format(
            name,
            rule,
        )
    elif __opts__['test']:
        ret['comment'] = 'iptables rule for {0!r} needs to be set as rulenum {1} ({2})'.format(
            name,
            rulenum,
            rule,
        )
    else:
        message =  __salt__['iptables.insert'](table, chain, rulenum, rule)
        if not message:
            ret['changes'] = {'locale': name}
            ret['result'] = True
            ret['comment'] = 'Set iptables rule for {0!r} as rulenum {1}: {2}'.format(
                name,
                rulenum,
                rule,
            )
        else:
            ret['result'] = False
            ret['comment'] = 'Failed to set iptables rule for {0!r} ({1})'.format(name, message)
    return ret


def _get_rulenum (table, chain, comment):
    rulenum = 1
    rules = __salt__['iptables.get_rules']()[table][chain]['rules']
    for i, rule in enumerate(rules):
        if rule.get('comment'):
            if rule['comment'][0] < comment:
                rulenum = i + 1
    return rulenum


SALT_ARGS = ('__id__', 'fun', 'state', '__env__', '__sls__',
             'order', 'watch', 'watch_in', 'require', 'require_in',
             'prereq', 'prereq_in')


def _filter_salt_args (kwargs):
    retargs = kwargs.copy()
    for arg in SALT_ARGS:
        if arg in retargs:
            del retargs[arg]
    return retargs


def _process_arg (arg, value):
    if value is None:
        return ()
    elif isinstance(value, bool):
        if value:
            return (arg, )
        else:
            return ('!', arg)
    else:
        if value.startswith('!'):
            return ('!', arg, "'{0}'".format(value[1:]))
        else:
            return (arg, "'{0}'".format(value))


def _process_flag (arg, value):
    if value is None:
        return ()
    elif value:
        return (arg, )
    else:
        return ('!', arg)
