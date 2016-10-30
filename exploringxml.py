import lxml.etree as etree
from collections import namedtuple
import pprint as pp

RedundantRule = namedtuple('RedundantRules',['refrule','duprules'])

redundant_rules = []

t = etree.parse('output.xml')

namespaces = {
              'r':'http://www.redseal.net/SCHEMAS/report/V1',
              'd':'http://www.redseal.net/SCHEMAS/report/access-rule'
             }

query = "//d:device[@name='AuthentifySRX']//d:bp-violation[@title='Redundant Rules']/d:file-lines/d:file-line"
elements = t.xpath(query,namespaces=namespaces)

for element in elements:

    if 'summary' in element.keys():
        refrule = element.get('line')
        duprules = []
    else:
        duprules.append(element.get('line'))

    redundant_rules.append(RedundantRule(refrule=refrule, duprules=duprules))

pp.pprint(redundant_rules)