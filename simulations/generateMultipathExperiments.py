from pathlib import Path

OUTPUT_FILE = Path("multipathExperiments.ini")

# ==============================
# Experiment Parameters
# ==============================

params = {
    "sim_time": "25s",
    "tcp_algorithm": "MpTcpMetaCubic",
    "packet_capacity": 100,
    "subflows": [2, 4, 8, 16, 32],  # easily extendable
}

# ==============================
# General Section Template
# ==============================

general_template = f"""
[General]

network = multipathdumbbell
sim-time-limit = {params["sim_time"]}
record-eventlog=false
cmdenv-express-mode = true
cmdenv-redirect-output = false
cmdenv-output-file = dctcpLog.txt
**.client*.tcp.conn-8.cmdenv-log-level = detail
cmdenv-log-prefix = %t | %m |

cmdenv-event-banners = false
**.cmdenv-log-level = off

**.**.tcp.conn-*.cwnd:vector(removeRepeats).vector-recording = true
**.**.tcp.conn-*.rtt:vector(removeRepeats).vector-recording = true
**.**.tcp.conn-*.srtt:vector(removeRepeats).vector-recording = true
**.**.tcp.conn-*.sndNxt:vector(removeRepeats).vector-recording = true
**.**.tcp.conn-*.throughput:vector(removeRepeats).vector-recording = true
**.**.tcp.conn-*.**.result-recording-modes = vector(removeRepeats)
**.**.goodput:vector(removeRepeats).vector-recording = true
**.**.goodput.result-recording-modes = vector(removeRepeats)
**.**.mbytesInFlight:vector(removeRepeats).vector-recording = true
**.**.mbytesInFlight.result-recording-modes = vector(removeRepeats)
**.scalar-recording=false
**.vector-recording=true
**.bin-recording=false 

**.goodputInterval = 1s
**.throughputInterval = 1s
**.tcp.typename = "MpTcp"
**.tcp.tcpAlgorithmClass = "{params["tcp_algorithm"]}"
**.tcp.advertisedWindow = 200000000
**.tcp.windowScalingSupport = true
**.tcp.windowScalingFactor = -1
**.tcp.increasedIWEnabled = true
**.tcp.delayedAcksEnabled = false
**.tcp.timestampSupport = true
**.tcp.ecnWillingness = false
**.tcp.nagleEnabled = true
**.tcp.stopOperationTimeout = 4000s
**.tcp.mss = 1448
**.tcp.sackSupport = true
**.client[*].numApps = 1
**.client[*].app[*].typename  = "MpTcpSessionApp"
*.client[*].app[0].tClose = -1s
*.client[*].app[0].sendBytes = 2GB
*.client[*].app[0].dataTransferMode = "bytecount"
*.client[*].app[0].statistic-recording = true

**.server[*].numApps = 1
**.server[*].app[*].typename  = "MpTcpSinkApp"
**.server[*].app[*].serverThreadModuleType = "tcpgoodputapplications.applications.tcpapp.TcpGoodputSinkAppThread"

**.**.queue.typename = "DropTailQueue"

**.additiveIncreasePercent = 0.05
**.eta = 0.95

**.alpha = 0.01
**.fixedAvgRTTVal = 0

**.tcp.initialSsthresh = 5792000
"""

# ==============================
# Config Template
# ==============================

config_template = """
[Config {name}]
extends = General 

**.numberOfSubflows = {subflows}

*.client[0].app[0].connectAddress = "server[0]"
*.client[0].app[0].tOpen  = 0.00846919251197291s
*.client[0].app[0].tSend = 0.00846919251197291s
*.client[0].app[0].sendBytes = 2GB

**.ppp[*].queue.packetCapacity = {packet_capacity}
"""

# ==============================
# Helper Functions
# ==============================

def subflow_name(n: int) -> str:
    names = {
        1: "OneSubflow",
        2: "TwoSubflows",
        4: "FourSubflows",
        8: "EightSubflows",
        16: "SixteenSubflows",
        32: "ThirtyTwoSubflows",
    }
    return names.get(n, f"{n}Subflows")


def generate_configs():
    configs = []

    for n in params["subflows"]:
        configs.append(
            config_template.format(
                name=subflow_name(n),
                subflows=n,
                packet_capacity=params["packet_capacity"],
            )
        )

    return "\n".join(configs)


# ==============================
# Write File
# ==============================

ini_contents = general_template + "\n" + generate_configs()

OUTPUT_FILE.write_text(ini_contents)

print(f"Generated {OUTPUT_FILE} with {len(params['subflows'])} experiments.")