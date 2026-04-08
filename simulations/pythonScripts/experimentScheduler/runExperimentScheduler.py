#!/usr/bin/env python

# Runs experimentScheduler
# runExperimentScheduler.py
#

import sys
import pandas as pd
import numpy as np
import random
from pathlib import Path
import os
import subprocess
import time
import re

try:
    import matplotlib.pyplot as plt
except ModuleNotFoundError:
    plt = None

if __name__ == "__main__":
    os.chdir(os.path.dirname(os.path.abspath(__file__)))

    startStep = 1
    endStep = 5
    currStep = 1
    cores = 2
    currentProc = 0
    processList = []
    experiment = "experimentScheduler"
    runs = 5
    runList = list(range(1,runs+1))
    oppRun = "../../../../bin/opp_run"
    oppScavetool = "../../../../bin/opp_scavetool"

    subprocess.Popen("python3 generateExperimentSchedulerScenarios.py", shell=True).communicate(timeout=30)
    subprocess.Popen("python3 generateExperimentSchedulerIniFile.py", shell=True).communicate(timeout=30)

    if(currStep <= endStep and currStep >= startStep): #STEP 1
        subprocess.Popen("rm experimentSchedulerrunTimes.txt", shell=True).communicate(timeout=30)

        with open('experimentSchedulerrunTimes.txt', 'w') as f1:
            expRunNum = 1
            f1.write("--experimentScheduler Runtimes (s)--")
            fileName =  '../../experimentScheduler/experimentScheduler.ini'
            iniFile = open(fileName, 'r').readlines()
            print("----------experimentScheduler simulations------------")
            for line in iniFile:
                if line.find('[Config') != -1:
                    match = re.search(r'Run(\d{1,5})\]', line)
                    if match and int(match.group(1)) in runList:
                        configName = (line[8:])[:-2]
                        progStart = time.time()
                        processList.append(subprocess.Popen(oppRun + " -r 0 -m -u Cmdenv -c " + configName +" -n .:..:../../src:../../../cubic/simulations:../../../cubic/src:../../../inet4.5/examples:../../../inet4.5/showcases:../../../inet4.5/src:../../../inet4.5/tests/validation:../../../inet4.5/tests/networks:../../../inet4.5/tutorials:../../../tcpPaced/src:../../../tcpPaced/simulations:../../../orbtcp/simulations:../../../orbtcp/src:../../../tcpGoodputApplications/simulations:../../../tcpGoodputApplications/src --image-path=../../../inet4.5/images -l ../../src/mptcp -l ../../../cubic/src/cubic -l ../../../inet4.5/src/INET -l ../../../tcpPaced/src/tcpPaced -l ../../../orbtcp/src/orbtcp -l ../../../tcpGoodputApplications/src/tcpGoodputApplications experimentScheduler.ini", shell=True, cwd='../../experimentScheduler', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
                        currentProc = currentProc + 1
                        print("Running simulation [" + configName + "]... (Run #" + str(currentProc) + ")")
                        if(currentProc == cores):
                            procCompleteNum = 0
                            for proc in processList:
                                proc.wait()
                                now = time.time()
                                f1.write("Run "+ str(expRunNum) + ": " + str(now-progStart))
                                procCompleteNum = procCompleteNum + 1
                                print("\tRun #" + str(procCompleteNum) + " is complete!")
                                expRunNum += 1
                            currentProc = 0
                            processList.clear()
                            print(" ... Running next batch of simulations! ...\n")
                    else:
                        continue

        for proc in processList:
            proc.wait()

    currStep += 1
    currentProc = 0
    processList.clear()

    if(currStep <= endStep and currStep >= startStep): #STEP 2
        currentProc = 0
        print("\nAll experiments in experimentScheduler have been run!\n")
        folderLoc =  '../../experimentScheduler/results/'
        print("------------ Generating CSV Files for experimentScheduler ------------")

        fileList = []
        for file in os.listdir(folderLoc):
            if(file.endswith(".vec")):
                f = os.path.join(folderLoc, file)
                processList.append(subprocess.Popen(oppScavetool + " export -o "+ "results/"+ file[:-4] + ".csv -F CSV-R " + "results/" + file , shell=True, cwd='../../experimentScheduler/'))
                currentProc = currentProc + 1
                print("Generating CSV file for [" + file + "]... (Run #" + str(currentProc) + ")")
                fileList.append(file)
                if(currentProc == cores):
                     for proc in processList:
                         proc.wait()
                     currentProc = 0
                     fileList.clear()
                     processList.clear()
                     print("     ... Running next batch! ...\n")

        time.sleep(5)
        for proc in processList:
            proc.wait()
        processList.clear()
        currentProc = 0
    print("CSVs created for experimentScheduler!\n")
    currStep += 1

    if(currStep <= endStep and currStep >= startStep): #STEP 3
        currentProc = 0
        print("Extracting CSV data!!\n")
        print("------------ Extracting CSV Files for experimentScheduler ------------")
        processListStr = []
        folderLoc =  '../../experimentScheduler/results/'
        for file in os.listdir(folderLoc):
            if(file.endswith(".csv")):
                configName = file[:-4].split("-#")[0]
                configParts = configName.split("_")
                if(len(configParts) < 4):
                    continue

                schedulerMode = "default"
                if(configParts[0] == "LowestRtt"):
                    schedulerMode = "lowestRtt"
                elif(configParts[0] == "DirectPull"):
                    schedulerMode = "directPull"

                subflows = "twosubflows"
                if(configParts[1] == "FourSubflows"):
                    subflows = "foursubflows"
                elif(configParts[1] == "EightSubflows"):
                    subflows = "eightsubflows"

                profile = "base50range10"
                if(configParts[2] != "Base50Range10"):
                    continue

                run = int(configParts[3].replace("Run", ""))
                if(run in runList):
                    filePath = '../../experimentScheduler/results/' + file
                    print("Extracting CSV file for " + configName)
                    processListStr.append("python3 extractSingleCsvFile.py " + filePath + " " + experiment + " " + schedulerMode + " " + subflows + " " + profile + " " + str(run))

        currentProc = 0
        time.sleep(5)
        while(len(processListStr) > 0):
            process = processListStr.pop()
            print(process + "\n")
            processList.append(subprocess.Popen(process, shell=True))
            currentProc += 1
            if(currentProc >= cores):
                for proc in processList:
                    proc.wait(timeout=1800)
                currentProc = 0
                print("Csv Extraction batch complete!\n")
                print("Extracting next batch!\n")
                processList.clear()
        for proc in processList:
            proc.wait(timeout=1800)
        processList.clear()
    currStep += 1

    if(currStep <= endStep and currStep >= startStep): #STEP 4
        subprocess.Popen("mkdir -p ../../experimentScheduler/plots", shell=True).communicate(timeout=10)
        print("\n-----Making plot directories for " + experiment + "-----\n")
        for schedulerMode in ["default", "lowestRtt", "directPull"]:
            subprocess.Popen("mkdir -p " + schedulerMode, shell=True, cwd='../../experimentScheduler/plots').communicate(timeout=10)
            for subflows in ["twosubflows", "foursubflows", "eightsubflows"]:
                subprocess.Popen("mkdir -p " + schedulerMode + "/" + subflows, shell=True, cwd='../../experimentScheduler/plots').communicate(timeout=10)
                for profile in ["base50range10"]:
                    subprocess.Popen("mkdir -p " + schedulerMode + "/" + subflows + "/" + profile, shell=True, cwd='../../experimentScheduler/plots').communicate(timeout=10)
                    for run in runList:
                        subprocess.Popen("mkdir -p " + schedulerMode + "/" + subflows + "/" + profile + "/run" + str(run), shell=True, cwd='../../experimentScheduler/plots').communicate(timeout=10)
    currStep += 1

    if(currStep <= endStep and currStep >= startStep): #STEP 5
        print("Plotting experimentScheduler goodput summary!\n")
        time.sleep(3)
        p = subprocess.Popen("python3 ../../pythonScripts/experimentScheduler/plotExperimentScheduler.py", shell=True, cwd='../../experimentScheduler/plots')
        p.wait(timeout=3600)
        time.sleep(1)
