#!/usr/bin/env python

# Generates ScenarioManager files for the MPTCP scheduler experiment
# generateExperimentSchedulerScenarios.py
#

import sys
import pandas as pd
import numpy as np
import random
from pathlib import Path
import json
import os

try:
    import matplotlib.pyplot as plt
except ModuleNotFoundError:
    plt = None

def build_rtt_range(numOfSubflows):
    if(numOfSubflows <= 1):
        return [50.0]

    rttStep = 10.0 / float(numOfSubflows - 1)
    return [50.0 + (subflowNum * rttStep) for subflowNum in range(numOfSubflows)]

def format_float(value):
    return "{:.6f}".format(value).rstrip('0').rstrip('.')

def int_to_word(num):
    d = { 0 : 'zero', 1 : 'one', 2 : 'two', 3 : 'three', 4 : 'four', 5 : 'five',
          6 : 'six', 7 : 'seven', 8 : 'eight', 9 : 'nine', 10 : 'ten',
          11 : 'eleven', 12 : 'twelve', 13 : 'thirteen', 14 : 'fourteen',
          15 : 'fifteen', 16 : 'sixteen', 17 : 'seventeen', 18 : 'eighteen',
          19 : 'nineteen', 20 : 'twenty',
          30 : 'thirty', 40 : 'forty', 50 : 'fifty', 60 : 'sixty',
          70 : 'seventy', 80 : 'eighty', 90 : 'ninety' }
    k = 1000
    m = k * 1000
    b = m * 1000
    t = b * 1000
    assert(0 <= num)
    if (num < 20):
        return d[num]
    if (num < 100):
        if num % 10 == 0: return d[num]
        else: return d[num // 10 * 10] + d[num % 10]
    if (num > 100):
        raise AssertionError('num is too large: %s' % str(num))

if __name__ == "__main__":
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    numOfClients = 1
    simSeed = 1
    random.seed(simSeed)

    scenarioRttDict = {
        "TwoSubflows_Base50Range10": build_rtt_range(2),
        "FourSubflows_Base50Range10": build_rtt_range(4),
        "EightSubflows_Base50Range10": build_rtt_range(8),
    }

    folderName = '../../experimentScheduler/scenarios/'
    Path(folderName).mkdir(parents=True, exist_ok=True)

    for existingScenario in Path(folderName).glob('*.xml'):
        if(existingScenario.stem not in scenarioRttDict):
            existingScenario.unlink()

    for scenarioName, scenarioRtts in scenarioRttDict.items():
        with open(folderName + '/' + scenarioName + '.xml', 'w') as f:
            f.write('<scenario>')
            f.write('\n    <at t="0">')
            for clientNum in range(numOfClients):
                for subflowNum in range(len(scenarioRtts)):
                    delay = scenarioRtts[subflowNum]
                    channelDelay = (delay-(0.5*2))/4
                    formattedChannelDelay = format_float(channelDelay)
                    f.write('\n        <set-channel-param src-module="client['+ str(clientNum) + ']" src-gate="pppg$o[' + str(subflowNum) + ']" par="delay" value="'+ formattedChannelDelay +'ms"/>')
                    f.write('\n        <set-channel-param src-module="router1['+ str(subflowNum) + ']" src-gate="pppg$o[0]" par="delay" value="'+ formattedChannelDelay +'ms"/>')
                    f.write('\n')
                    f.write('\n        <set-channel-param src-module="server['+ str(clientNum) + ']" src-gate="pppg$o[' + str(subflowNum) + ']" par="delay" value="'+ formattedChannelDelay +'ms"/>')
                    f.write('\n        <set-channel-param src-module="router2['+ str(subflowNum) + ']" src-gate="pppg$o[0]" par="delay" value="'+ formattedChannelDelay +'ms"/>')
                    f.write('\n')

            f.write('\n    </at>')
            f.write('\n</scenario>')

        print("Generated scenario " + scenarioName + " with RTTs " + str(scenarioRtts))
