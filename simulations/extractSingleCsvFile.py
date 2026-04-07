#!/usr/bin/env python

# Extract vectors from OMNeT++ CSV
# usage:
# python3 extractSingleCsvFile.py <csvFile> <experimentName>

import sys
import pandas as pd
import numpy as np
from pathlib import Path
import os
import re
import time as termTime


def parse_if_number(s):
    try:
        return float(s)
    except:
        return True if s == "true" else False if s == "false" else s if s else None


def parse_ndarray(s):
    return np.fromstring(s, sep=' ') if s else None


def getResults(file):
    resultsFile = pd.read_csv(
        file,
        converters={
            'attrvalue': parse_if_number,
            'binedges': parse_ndarray,
            'binvalues': parse_ndarray,
            'vectime': parse_ndarray,
            'vecvalue': parse_ndarray
        }
    )

    vectors = resultsFile[resultsFile.type == 'vector']
    return vectors


if __name__ == "__main__":

    filePath = sys.argv[1]
    experiment = sys.argv[2]

    vectorsToExtract = [
        "goodput",
        "rtt",
        "cwnd",
        "queueLength",
        "throughput"
    ]

    rawResults = getResults(filePath)

    baseDir = Path("csvs") / experiment
    baseDir.mkdir(parents=True, exist_ok=True)

    for vec in vectorsToExtract:

        results = rawResults.loc[
            rawResults['name'] == f"{vec}:vector(removeRepeats)"
        ]

        for mod in range(len(results.vecvalue.to_numpy())):

            if results.vecvalue.to_numpy()[mod] is None:
                continue

            val = results.vecvalue.to_numpy()[mod]
            time = results.vectime.to_numpy()[mod]
            modName = results.module.to_numpy()[mod]

            # clean module name
            if 'thread' in modName:
                modName = re.sub(r'\.thread_\d+', '', modName)

            outputDir = baseDir / modName
            outputDir.mkdir(parents=True, exist_ok=True)

            finallist = pd.DataFrame({
                "time": time,
                vec: val
            })

            outFile = outputDir / f"{vec}.csv"
            finallist.to_csv(outFile, index=False)

    termTime.sleep(0.5)