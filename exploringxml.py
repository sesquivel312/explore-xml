import lxml.etree as etree
from collections import namedtuple
import pprint as pp

# RedundantRule = namedtuple('RedundantRules',['refrule','duprules'])

redundant_rules = {}

t = etree.parse('output.xml')

namespaces = {
              'r':'http://www.redseal.net/SCHEMAS/report/V1',
              'd':'http://www.redseal.net/SCHEMAS/report/access-rule'
             }

query = "//d:device[@name='AuthentifySRX']//d:bp-violation[@check-id=2]/d:file-lines/d:file-line"
elems = t.xpath(query,namespaces=namespaces)

for e in elems:
    if 'is-first-in-display-group' in e.keys():  # if this is the start of a redundant rule group ...
        refrule = e.get('line')  # then extract the line # of the "reference rule"
        if not redundant_rules[refrule]:  # if this is the first time we've seen the reference rule ...
            redundant_rules[refrule] = set([])  # then create a list to hold the assoc'd redundant rules
    else:
        redundant_rules[refrule].add(e.get('line'))  # this rule is redundant, add to set (to avoid dups)

pp.pprint(redundant_rules)