#!/usr/bin/env python

# Generates the INI file for the MPTCP scheduler experiment
# generateExperimentSchedulerIniFile.py
#

import sys
import pandas as pd
import numpy as np
import random
from pathlib import Path
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

def get_two_bdp_packets(rttMilliseconds):
    bandwidthBytesPerSecond = 50 * 125000
    rttSeconds = float(rttMilliseconds) / 1000.0
    bdpBytes = bandwidthBytesPerSecond * rttSeconds
    return int((bdpBytes * 2.0) / 1448)

if __name__ == "__main__":
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    simSeed = 1999
    numOfRuns = 5
    schedulerModes = ["default", "lowestRtt", "directPull"]
    fileName = '../../experimentScheduler/experimentScheduler.ini'
    random.seed(simSeed)

    scenarioRttDict = {
        "TwoSubflows_Base50Range10": build_rtt_range(2),
        "FourSubflows_Base50Range10": build_rtt_range(4),
        "EightSubflows_Base50Range10": build_rtt_range(8),
    }

    print('\nGenerating ini file for experimentScheduler...')

    with open(fileName, 'w') as f:
        f.write('[General]' + '\n')
        f.write('\n' + 'network = experimentSchedulerDumbbell')
        f.write('\n' + 'result-dir = results')
        f.write('\n' + 'record-eventlog=false')
        f.write('\n' + 'cmdenv-express-mode = true')
        f.write('\n' + 'cmdenv-redirect-output = false')
        f.write('\n' + 'cmdenv-output-file = dctcpLog.txt')
        f.write('\n' + '**.client*.tcp.conn-8.cmdenv-log-level = detail')
        f.write('\n' + 'cmdenv-log-prefix = %t | %m |\n\n')
        f.write('\n' + 'cmdenv-event-banners = false')
        f.write('\n' + '**.cmdenv-log-level = off\n')

        f.write('\n' + '**.**.tcp.conn-*.cwnd:vector(removeRepeats).vector-recording = true')
        f.write('\n' + '**.**.tcp.conn-*.rtt:vector(removeRepeats).vector-recording = true')
        f.write('\n' + '**.**.tcp.conn-*.srtt:vector(removeRepeats).vector-recording = true')
        f.write('\n' + '**.**.tcp.conn-*.throughput:vector(removeRepeats).vector-recording = true')
        f.write('\n' + '**.**.tcp.conn-*.mbytesInFlight:vector(removeRepeats).vector-recording = true')
        f.write('\n' + '**.**.tcp.conn-*.**.result-recording-modes = vector(removeRepeats)')

        f.write('\n' + '**.**.queue.queueLength:vector(removeRepeats).vector-recording = true')
        f.write('\n' + '**.**.queue.queueLength.result-recording-modes = vector(removeRepeats)')

        f.write('\n' + '**.**.goodput:vector(removeRepeats).vector-recording = true')
        f.write('\n' + '**.**.goodput.result-recording-modes = vector(removeRepeats)')

        f.write('\n' + '**.scalar-recording=false')
        f.write('\n' + '**.vector-recording=false')
        f.write('\n' + '**.bin-recording=false\n')

        f.write('\n' + '**.goodputInterval = 1s')
        f.write('\n' + '**.throughputInterval = 1s')

        f.write('\n' + '**.tcp.typename = "MpTcp"')
        f.write('\n' + '**.tcp.tcpAlgorithmClass = "MpTcpMetaCubic"')
        f.write('\n' + '**.schedulerMode = "default"')
        f.write('\n' + '**.startAllSubflowsAtBeginning = true')
        f.write('\n' + '**.tcp.advertisedWindow = 200000000')
        f.write('\n' + '**.tcp.windowScalingSupport = true')
        f.write('\n' + '**.tcp.windowScalingFactor = -1')
        f.write('\n' + '**.tcp.increasedIWEnabled = true')
        f.write('\n' + '**.tcp.delayedAcksEnabled = false')
        f.write('\n' + '**.tcp.timestampSupport = true')
        f.write('\n' + '**.tcp.ecnWillingness = false')
        f.write('\n' + '**.tcp.nagleEnabled = true')
        f.write('\n' + '**.tcp.stopOperationTimeout = 4000s')
        f.write('\n' + '**.tcp.mss = 1448')
        f.write('\n' + '**.tcp.sackSupport = true')
        f.write('\n' + '**.tcp.initialSsthresh = ' + str(4000*1448))

        f.write('\n' + '**.client[*].numApps = 1')
        f.write('\n' + '**.client[*].app[*].typename  = "MpTcpSessionApp"')
        f.write('\n' + '*.client[*].app[0].tClose = -1s')
        f.write('\n' + '*.client[*].app[0].sendBytes = 2GB')
        f.write('\n' + '*.client[*].app[0].dataTransferMode = "bytecount"')
        f.write('\n' + '*.client[*].app[0].statistic-recording = true\n')

        f.write('\n' + '**.server[*].numApps = 1')
        f.write('\n' + '**.server[*].app[*].typename  = "MpTcpSinkApp"')
        f.write('\n' + '**.server[*].app[*].serverThreadModuleType = "tcpgoodputapplications.applications.tcpapp.TcpGoodputSinkAppThread"\n')

        f.write('\n' + '**.**.queue.typename = "DropTailQueue"\n')
        f.write('\n' + '**.ppp[*].queue.packetCapacity = 100\n')

        for schedulerMode in schedulerModes:
            for scenarioName, scenarioRtts in scenarioRttDict.items():
                numOfSubflows = len(scenarioRtts)

                schedulerTitle = "Default"
                if(schedulerMode == "lowestRtt"):
                    schedulerTitle = "LowestRtt"
                elif(schedulerMode == "directPull"):
                    schedulerTitle = "DirectPull"

                for i in range(numOfRuns):
                    configName = schedulerTitle + "_" + str(scenarioName) + "_Run" + str(i+1)
                    firstSubflowStartTimeSeconds = random.uniform(0, (float(scenarioRtts[0]) / 1000.0) * 50.0)
                    subflowStartOffsetsSeconds = [0.0]
                    subflowStartTimes = ["0.000000s"]
                    for rtt in scenarioRtts[1:]:
                        startOffsetSeconds = random.uniform(0, (float(rtt) / 1000.0) * 50.0)
                        subflowStartOffsetsSeconds.append(startOffsetSeconds)
                        subflowStartTimes.append("{:.6f}s".format(startOffsetSeconds))

                    maxRttSeconds = max(scenarioRtts) / 1000.0
                    latestSubflowStartTimeSeconds = firstSubflowStartTimeSeconds + max(subflowStartOffsetsSeconds)
                    simTimeLimit = latestSubflowStartTimeSeconds + (maxRttSeconds * 500.0)
                    print(configName)
                    f.write('\n' + '[Config ' + configName + ']')
                    f.write('\n' + 'extends = General \n')

                    f.write('\n' + 'seed-set = ' + str(simSeed) + '\n')
                    f.write('\n' + '**.numberOfSubflows = ' + str(numOfSubflows))
                    f.write('\n' + '**.schedulerMode = "' + str(schedulerMode) + '"')
                    f.write('\n' + '**.subflowStartTimes = "' + " ".join(subflowStartTimes) + '"')
                    for pathIndex in range(len(scenarioRtts)):
                        queuePacketCapacity = get_two_bdp_packets(scenarioRtts[pathIndex])
                        f.write('\n' + '*.router1[' + str(pathIndex) + '].ppp[1].queue.packetCapacity = ' + str(queuePacketCapacity))
                        f.write('\n' + '*.router2[' + str(pathIndex) + '].ppp[1].queue.packetCapacity = ' + str(queuePacketCapacity))

                    f.write('\n' + '*.client[0].app[0].connectAddress =  "server[0]"')
                    f.write('\n' + '*.client[0].app[0].tOpen = {:.6f}s'.format(firstSubflowStartTimeSeconds))
                    f.write('\n' + '*.client[0].app[0].tSend = {:.6f}s\n'.format(firstSubflowStartTimeSeconds))

                    f.write('\n' + '*.scenarioManager.script = xmldoc("scenarios/'+ str(scenarioName) + '.xml")\n')
                    f.write('\n' + 'sim-time-limit = {:.6f}s \n'.format(simTimeLimit))

    print('\nINI file generated!')
