#!/usr/bin/python

# read config file
# output to csv

import ConfigParser
import re
import csv

config = ConfigParser.ConfigParser()
config.read("config")

# 
# Create the Output File
# 
ofile = config.get("Output", "filename")
output = csv.writer( open(ofile, "wb"), quoting=csv.QUOTE_NONNUMERIC )
output.writerow(['TYPE', 'FILENAME', 'ID', 'SRC INTERFACE', 'DST INTERFACE', 
    'SCR', 'DST', 'SERVICE', 'ACTION', 'STATUS'])

# 
# Parse Juniper Firewall
# 
for filename, filepath in config.items('Juniper Firewall'):
    
    fwbrand = 'Juniper'
    file = open(filepath, 'r').readlines()
    rules_juniper = {}
    start = 0

    patternnonat = re.compile(r'(?:set policy id)\s(?P<id>\d+)\s(?:from|name\s".+?"\sfrom)\s"(?P<srcintf>.+?)"\sto\s"(?P<dstintf>.+?)"\s+"(?P<src>.+?)"\s"(?P<dst>.+?)"\s"(?P<service>.+?)"\s(?P<action>reject|permit|deny)')
    patternwithnat = re.compile(r'(?:set policy id)\s(?P<id>\d+)\s(?:from|name\s".+?"\sfrom)\s"(?P<srcintf>.+?)"\sto\s"(?P<dstintf>.+?)"\s+"(?P<src>.+?)"\s"(?P<dst>.+?)"\s"(?P<service>.+?)"\s(?:.+)(?P<action>permit|deny)')
    patternsrc = re.compile(r'(?:set src-address)\s"(?P<src>.+?)"')
    patterndst = re.compile(r'(?:set dst-address)\s"(?P<dst>.+?)"')
    patternstatus = re.compile(r'set policy id \d+ disable')
    patternsvc = re.compile(r'(?:set service)\s"(?P<service>.+)"')

    for line in file:
        
        if re.search(r'set policy id', line):
            start = 1

        if start == 0: continue

        # i capture patern without nat
        patternnonatmatch = patternnonat.match(line.rstrip())
        if patternnonatmatch:
            rules_juniper['id'] = patternnonatmatch.group('id')
            rules_juniper['srcintf'] = patternnonatmatch.group('srcintf')
            rules_juniper['dstintf'] = patternnonatmatch.group('dstintf')
            rules_juniper['srcaddr'] = [patternnonatmatch.group('src')]
            rules_juniper['dstaddr'] = [patternnonatmatch.group('dst')]
            rules_juniper['service'] = [patternnonatmatch.group('service')]
            rules_juniper['action'] = patternnonatmatch.group('action')

        # i capture paterrn with nat
        patternwithnatmatch = patternwithnat.match(line.rstrip())
        if patternwithnatmatch:
            rules_juniper['id'] = patternwithnatmatch.group('id')
            rules_juniper['srcintf'] = patternwithnatmatch.group('srcintf')
            rules_juniper['dstintf'] = patternwithnatmatch.group('dstintf')
            rules_juniper['srcaddr'] = [patternwithnatmatch.group('src')]
            rules_juniper['dstaddr'] = [patternwithnatmatch.group('dst')]
            rules_juniper['service'] = [patternwithnatmatch.group('service')]
            rules_juniper['action'] = patternwithnatmatch.group('action')

        # if i capture line with src-address patern
        patternsrcmatch = patternsrc.match(line)
        if patternsrcmatch:
            rules_juniper['srcaddr'].append( patternsrcmatch.group('src') )

        # if i capture line dst-address
        patterndstmatch = patterndst.match(line)
        if patterndstmatch:
            rules_juniper['dstaddr'].append(patterndstmatch.group('dst'))

        # if i capture line with status disable
        patternstatusmatch = patternstatus.match(line.rstrip())
        if (patternstatusmatch):
            rules_juniper['status'] = 'disable'

        # if i capture line with services
        patternsvcmatch = patternsvc.match(line)
        if patternsvcmatch:
            rules_juniper['service'].append(patternsvcmatch.group('service'))

        # Oh! i see exit line, it's time to compile all the rule!
        if ( re.match(r'exit', line) and len(rules_juniper) > 3 ):
            for src in rules_juniper['srcaddr']:
                for dst in rules_juniper['dstaddr']:
                    servicelist = ' '.join(rules_juniper['service'])
                    statuslist = rules_juniper.get('status', 'enable')
                    row = [fwbrand, filename.upper(), rules_juniper['id'], rules_juniper['srcintf'], rules_juniper['dstintf'], src, dst, servicelist, rules_juniper['action'], statuslist]
                    output.writerow(row)

            # i empty back the rules_juniper dictionary
            rules_juniper = {}


# 
# Parse Fortinet firewall
# 
for filename, filepath in config.items('Fortinet Firewall'):

    fwbrand = 'Fortinet'
    file = open(filepath, 'r').readlines()
    fortirule = {}
    startParse = 0

    for line in file:

        if re.match(r'config firewall policy', line):
            startParse = 1

        if startParse == 0: continue

        fwid = re.search(r'edit\s(\d+)', line)
        if fwid:
            fortirule['id'] = fwid.group(1)

        srcintf = re.search(r'(?:set srcintf)\s"(?P<srcintf>.+?)"', line)
        if srcintf:
            fortirule['srcintf'] = srcintf.group('srcintf')

        dstintf = re.search(r'(?:set dstintf)\s"(?P<dstintf>.+?)"', line)
        if dstintf:
            fortirule['dstintf'] = dstintf.group('dstintf')

        if re.search(r'set srcaddr',line):
            srcaddr = re.findall(r'"(.+?)"', line)
            fortirule['srcaddr'] = srcaddr

        if re.search(r'set dstaddr', line):
            dstaddr = re.findall(r'"(.+?)"', line)
            fortirule['dstaddr'] = dstaddr

        action = re.search(r'(?:set action)\s(?P<action>.+)', line)
        if action:
            fortirule['action'] = action.group('action')

        if re.search(r'set service\s', line):
            service = re.findall(r'"(.+?)"', line)
            fortirule['service'] = service

        status = re.search(r'(?:set status)\s(?P<status>.+)', line)
        if status:
            fortirule['status'] = status.group('status')

        if re.search(r'next', line):
            for src in fortirule['srcaddr']:
                for dst in fortirule['dstaddr']:
                    servicelistf = ' '.join(fortirule['service'])
                    statuslistf = fortirule.get('status', 'enable')
                    actionf = fortirule.get('action', 'deny')

                    row = [fwbrand, filename.upper(), fortirule['id'], fortirule['srcintf'], fortirule['dstintf'], src, dst, servicelistf, actionf, statuslistf]
                    output.writerow(row)

            # reset back the dict to empty before next rule
            fortirule = {}
            
        # stop parse after end of frewall config
        if re.match(r'end', line):
            startParse = 0


