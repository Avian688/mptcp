#!/usr/bin/env python

import pandas as pd
import os, sys
import numpy as np

HAS_MATPLOTLIB = True
try:
    import matplotlib.pyplot as plt
except ModuleNotFoundError:
    HAS_MATPLOTLIB = False
    plt = None

try:
    import scienceplots
    if(HAS_MATPLOTLIB):
        plt.style.use('science')
except ModuleNotFoundError:
    scienceplots = None

if(HAS_MATPLOTLIB):
    plt.rcParams['text.usetex'] = False
    plt.rcParams['axes.labelsize'] = "medium"
    plt.rcParams['xtick.labelsize'] = "medium"
    plt.rcParams['ytick.labelsize'] = "medium"

SCHEDULERS = ['default', 'lowestRtt', 'directPull']
SCHEDULERDICT = {'default': "Default", 'lowestRtt': "Lowest RTT", 'directPull': "Direct Pull"}
SUBFLOWS = [('twosubflows', 2), ('foursubflows', 4), ('eightsubflows', 8)]
PROFILES = ['base50range10']
PROFILEDICT = {'base50range10': "Base 50ms, 10ms RTT Spread"}
RUNS = [1, 2, 3, 4, 5]

LINEWIDTH = 0.60
ELINEWIDTH = 0.75
CAPTHICK = ELINEWIDTH
CAPSIZE = 2

def plot_points_subflows(ax, df, data, error, marker, label):
    if not df.empty:
        xvals = df.index
        yvals = df[data]
        yerr = df[error]
        markers, caps, bars = ax.errorbar(
            xvals, yvals,
            yerr=yerr,
            marker=marker,
            linewidth=LINEWIDTH,
            elinewidth=ELINEWIDTH,
            capsize=CAPSIZE,
            capthick=CAPTHICK,
            label=label
        )
        [bar.set_alpha(0.5) for bar in bars]
        [cap.set_alpha(0.5) for cap in caps]

if __name__ == "__main__":
    data = []
    for scheduler in SCHEDULERS:
        for subflowFolder, subflowCount in SUBFLOWS:
            for profile in PROFILES:
                overallGoodputs = []
                steadyGoodputs = []
                for run in RUNS:
                    PATH = '../csvs/' + scheduler + '/' + subflowFolder + '/' + profile + '/run' + str(run) + '/'
                    receiverPath = PATH + 'experimentSchedulerDumbbell.server[0].app[0]/goodput.csv'
                    if os.path.exists(receiverPath):
                        receiver = pd.read_csv(receiverPath).reset_index(drop=True)
                        if(not receiver.empty):
                            overallGoodputs.append(receiver['goodput'].mean()/1000000)
                            keepLast = max(1, int(len(receiver.index) * 0.5))
                            steadyGoodputs.append(receiver.tail(keepLast)['goodput'].mean()/1000000)
                    else:
                        print("File %s not found." % receiverPath)

                if len(overallGoodputs) > 0:
                    data.append([
                        scheduler,
                        subflowFolder,
                        subflowCount,
                        profile,
                        np.mean(overallGoodputs),
                        np.std(overallGoodputs),
                        np.mean(steadyGoodputs),
                        np.std(steadyGoodputs)
                    ])

    summaryData = pd.DataFrame(
        data,
        columns=[
            'scheduler', 'subflowsFolder', 'subflowsCount', 'profile',
            'overallMeanGoodput', 'overallStdGoodput',
            'steadyMeanGoodput', 'steadyStdGoodput'
        ]
    )
    summaryData.to_csv("summaryGoodput.csv", index=False)

    if(not HAS_MATPLOTLIB):
        print("summaryGoodput.csv written, but matplotlib is not installed so plots were skipped.")
        sys.exit(0)

    for profile in PROFILES:
        fig, ax = plt.subplots(figsize=(4.5,1.6))
        ax.set_ylim(bottom=0)
        for scheduler, marker in [('default', 'o'), ('lowestRtt', '^'), ('directPull', 's')]:
            df = summaryData[(summaryData['scheduler'] == scheduler) & (summaryData['profile'] == profile)].set_index('subflowsCount')
            plot_points_subflows(
                ax, df,
                'steadyMeanGoodput',
                'steadyStdGoodput',
                marker, SCHEDULERDICT.get(scheduler)
            )

        ax.set(xscale='linear', xlabel='Number of Subflows', ylabel='Goodput (Mbps)')
        ax.set_title(PROFILEDICT.get(profile))
        ax.set_xticks([2, 4, 8])
        ax.grid(True)

        handles, labels = ax.get_legend_handles_labels()
        line_handles = [h[0] if isinstance(h, tuple) else h for h in handles]
        legend_map = dict(zip(labels, line_handles))
        handles_top = [
            legend_map.get('Default'),
            legend_map.get('Lowest RTT'),
            legend_map.get('Direct Pull')
        ]
        labels_top = ['Default', 'Lowest RTT', 'Direct Pull']
        legend_top = plt.legend(
            handles_top, labels_top,
            ncol=3,
            loc='upper center',
            bbox_to_anchor=(0.5, 1.25),
            columnspacing=1.0,
            handletextpad=0.5,
            labelspacing=0.1,
            borderaxespad=0.0,
            fontsize='small'
        )
        plt.gca().add_artist(legend_top)
        plt.tight_layout()
        plt.savefig("goodput_" + profile + ".pdf", dpi=1080)
        plt.close(fig)

    print("Experiment scheduler plots generated.")
