#!/usr/bin/env python

# Runs Multipath Experiments
# runMultipathExperiments.py

import os
import subprocess
import time
import re
from pathlib import Path

def get_config_names(ini_file):
    configs = []
    with open(ini_file) as f:
        for line in f:
            if line.startswith("[Config"):
                name = line.split()[1].replace("]","")
                configs.append(name)
    return configs


if __name__ == "__main__":

    startStep = 1
    endStep = 6
    currStep = 1

    cores = 5
    currentProc = 0
    processList = []

    experiment = "multipath"
    iniFile = "multipathExperiments.ini"

    subflowConfigs = [
        "OneSubflow",
        "TwoSubflows",
        "FourSubflows",
        "EightSubflows",
        "SixteenSubflows",
        "ThirtyTwoSubflows"
    ]

    resultsFolder = "results"
    csvFolder = "csvs"

    Path(csvFolder).mkdir(exist_ok=True)

    ############################################
    # STEP 1 - RUN SIMULATIONS
    ############################################
    
    if(currStep <= endStep and currStep >= startStep):
    
        configs = get_config_names(iniFile)
    
        print("------------ Running Multipath Experiments ------------")
    
        base = "../../"
    
        opp_run_template = f"""
        opp_run -r 0 -m -u Cmdenv -c {{config}}
        -n .:../src:{base}cubic/simulations:{base}cubic/src:{base}inet4.5/examples:{base}inet4.5/showcases:{base}inet4.5/src:{base}inet4.5/tests/validation:{base}inet4.5/tests/networks:{base}inet4.5/tutorials:{base}tcpPaced/src:{base}tcpPaced/simulations:{base}orbtcp/simulations:{base}orbtcp/src:{base}tcpGoodputApplications/simulations:{base}tcpGoodputApplications/src
        -x "inet.common.selfdoc;inet.linklayer.configurator.gatescheduling.z3;inet.emulation;inet.showcases.visualizer.osg;inet.examples.emulation;inet.showcases.emulation;inet.transportlayer.tcp_lwip;inet.applications.voipstream;inet.visualizer.osg;inet.examples.voipstream"
        --image-path={base}inet4.5/images
        -l {base}mptcp/src/mptcp
        -l {base}cubic/src/cubic
        -l {base}inet4.5/src/INET
        -l {base}tcpPaced/src/tcpPaced
        -l {base}orbtcp/src/orbtcp
        -l {base}tcpGoodputApplications/src/tcpGoodputApplications
        multipathExperiments.ini
        """
    
        runNum = 1
    
        for configName in configs:
    
            cmd = opp_run_template.format(config=configName).replace("\n", " ")
    
            processList.append(
                subprocess.Popen(
                    cmd,
                    shell=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
            )
    
            currentProc += 1
            print(f"Running simulation [{configName}]... (Run #{runNum})")
    
            runNum += 1
    
            if(currentProc == cores):
    
                procCompleteNum = 0
                for proc in processList:
                    proc.wait()
                    procCompleteNum += 1
                    print(f"\tRun #{procCompleteNum} complete!")
    
                currentProc = 0
                processList.clear()
    
        for proc in processList:
            proc.wait()
    
        processList.clear()
        currentProc = 0

    currStep += 1

    ############################################
    # STEP 2 - CONVERT VEC TO CSV
    ############################################

    if(currStep <= endStep and currStep >= startStep):

        print("\n------------ Generating CSV files ------------")

        Path(resultsFolder).mkdir(exist_ok=True)

        vecFiles = [f for f in os.listdir(resultsFolder) if f.endswith(".vec")]

        for vec in vecFiles:

            csvName = vec.replace(".vec",".csv")

            processList.append(
                subprocess.Popen(
                    "opp_scavetool export -o "
                    + resultsFolder + "/" + csvName +
                    " -F CSV-R "
                    + resultsFolder + "/" + vec,
                    shell=True
                )
            )

            currentProc += 1
            print("Generating CSV for [" + vec + "]")

            if(currentProc == cores):
                for proc in processList:
                    proc.wait()

                processList.clear()
                currentProc = 0
                print("Batch complete\n")

        for proc in processList:
            proc.wait()

        processList.clear()
        currentProc = 0

        print("CSV generation complete\n")

    currStep += 1

    ############################################
    # STEP 3 - EXTRACT CSV DATA
    ############################################

    if(currStep <= endStep and currStep >= startStep):

        print("------------ Extracting CSV Data ------------")

        csvFiles = [f for f in os.listdir(resultsFolder) if f.endswith(".csv")]

        for csv in csvFiles:

            name = csv.replace(".csv", "")
            matched = name.split("-#")[0]
            
            if matched not in subflowConfigs:
                continue

            filePath = Path(resultsFolder) / csv

            cmd = f"python3 extractSingleCsvFile.py {filePath} {matched}"

            processList.append(subprocess.Popen(cmd, shell=True))

            currentProc += 1

            print("Extracting " + str(filePath))

            if(currentProc >= cores):

                for proc in processList:
                    proc.wait()

                processList.clear()
                currentProc = 0
                print("Extraction batch complete\n")

        for proc in processList:
            proc.wait()

        processList.clear()
        currentProc = 0

    currStep += 1


    print("\nAll Multipath Experiments Complete!\n")
    
    
    ############################################
    # STEP 4 - CREATE PLOT DIRECTORIES
    ############################################
    
    if(currStep <= endStep and currStep >= startStep):
    
        print("\n-----Creating plot directories-----\n")
    
        plotRoot = Path("plots") / experiment
    
        subprocess.Popen("mkdir -p plots", shell=True).communicate(timeout=20)
        subprocess.Popen(f"mkdir -p {plotRoot}", shell=True).communicate(timeout=20)
    
        for cfg in subflowConfigs:
    
            cfgPlotDir = plotRoot / cfg
            cfgPlotDir.mkdir(parents=True, exist_ok=True)
    
            print(f"Created plot directory for {cfg}")
    
    currStep += 1
    
    
    ############################################
    # STEP 5 - GENERATE GOODPUT PLOTS
    ############################################
    
    if(currStep <= endStep and currStep >= startStep):
    
        print("\n-----Plotting Goodput Graphs-----\n")
    
        for cfg in subflowConfigs:
    
            csvDir = Path(csvFolder) / cfg
            plotDir = Path("plots") / experiment / cfg
    
            if not csvDir.exists():
                continue
    
            goodputFiles = []
    
            for root, dirs, files in os.walk(csvDir):
                for file in files:
                    if file == "goodput.csv":
                        goodputFiles.append(str((Path(root) / file).resolve()))
    
            if len(goodputFiles) == 0:
                continue
    
            print(f"Plotting {cfg} goodput graph with {len(goodputFiles)} flows")
    
            cmd = "python3 ../../../plotGoodput.py " + " ".join(goodputFiles)
    
            p = subprocess.Popen(
                cmd,
                shell=True,
                cwd=plotDir
            )
    
            p.wait(timeout=3600)
    
    currStep += 1