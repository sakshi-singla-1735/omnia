# These are the slurm options for version - 25.11
import re
from enum import Enum


class SlurmParserEnum(str, Enum):
    """Enumeration of Slurm configuration parameter types for parsing and validation."""

    S_P_IGNORE = "none"         # no value / ignored
    S_P_STRING = "str"          # generic string
    S_P_LONG = "int"            # integer (Python has only int)
    S_P_UINT16 = "int"          # unsigned int mapped to int
    S_P_UINT32 = "int"          # unsigned int mapped to int
    S_P_UINT64 = "int"          # unsigned int mapped to int
    S_P_POINTER = "object"      # generic object / pointer
    S_P_ARRAY = "list"          # array-like -> list
    S_P_BOOLEAN = "bool"        # boolean
    S_P_LINE = "str"            # line of text
    S_P_EXPLINE = "str"         # expanded line of text
    S_P_PLAIN_STRING = "str"    # plain string
    S_P_FLOAT = "float"         # floating point
    S_P_DOUBLE = "float"        # Python float is double precision
    S_P_LONG_DOUBLE = "float"   # approximate with float


# Convenience aliases (if other modules refer to S_P_* directly)
S_P_IGNORE = SlurmParserEnum.S_P_IGNORE
S_P_STRING = SlurmParserEnum.S_P_STRING
S_P_LONG = SlurmParserEnum.S_P_LONG
S_P_UINT16 = SlurmParserEnum.S_P_UINT16
S_P_UINT32 = SlurmParserEnum.S_P_UINT32
S_P_UINT64 = SlurmParserEnum.S_P_UINT64
S_P_POINTER = SlurmParserEnum.S_P_POINTER
S_P_ARRAY = SlurmParserEnum.S_P_ARRAY
S_P_BOOLEAN = SlurmParserEnum.S_P_BOOLEAN
S_P_LINE = SlurmParserEnum.S_P_LINE
S_P_EXPLINE = SlurmParserEnum.S_P_EXPLINE
S_P_PLAIN_STRING = SlurmParserEnum.S_P_PLAIN_STRING
S_P_FLOAT = SlurmParserEnum.S_P_FLOAT
S_P_DOUBLE = SlurmParserEnum.S_P_DOUBLE
S_P_LONG_DOUBLE = SlurmParserEnum.S_P_LONG_DOUBLE


downnodes_options = {
    "Reason": S_P_STRING,
    "State": S_P_STRING,
}


nodename_options = {
    "BcastAddr": S_P_STRING,
    "Boards": S_P_UINT16,
    "CoreSpecCount": S_P_UINT16,
    "CoresPerSocket": S_P_UINT16,
    "CPUs": S_P_UINT16,
    "CPUSpecList": S_P_STRING,
    "CpuBind": S_P_STRING,
    "Feature": S_P_STRING,
    "Features": S_P_STRING,
    "Gres": S_P_STRING,
    "GresConf": S_P_STRING,
    "MemSpecLimit": S_P_UINT64,
    "NodeAddr": S_P_STRING,
    "NodeHostname": S_P_STRING,
    "Parameters": S_P_STRING,
    "Port": S_P_STRING,
    "Procs": S_P_UINT16,
    "RealMemory": S_P_UINT64,
    "Reason": S_P_STRING,
    "RestrictedCoresPerGPU": S_P_UINT16,
    "Sockets": S_P_UINT16,
    "SocketsPerBoard": S_P_UINT16,
    "State": S_P_STRING,
    "ThreadsPerCore": S_P_UINT16,
    "TmpDisk": S_P_UINT32,
    "Topology": S_P_STRING,
    "TRESWeights": S_P_STRING,
    "Weight": S_P_UINT32,
}


nodeset_options = {
    "Feature": S_P_STRING,
    "Nodes": S_P_STRING,
}


partition_options = {
    "AllocNodes": S_P_STRING,
    "AllowAccounts": S_P_STRING,
    "AllowGroups": S_P_STRING,
    "AllowQos": S_P_STRING,
    "Alternate": S_P_STRING,
    "CpuBind": S_P_STRING,
    "DefCPUPerGPU": S_P_UINT64,
    "DefMemPerCPU": S_P_UINT64,
    "DefMemPerGPU": S_P_UINT64,
    "DefMemPerNode": S_P_UINT64,
    "Default": S_P_BOOLEAN,
    "DefaultTime": S_P_STRING,
    "DenyAccounts": S_P_STRING,
    "DenyQos": S_P_STRING,
    "DisableRootJobs": S_P_BOOLEAN,
    "ExclusiveUser": S_P_BOOLEAN,
    "ExclusiveTopo": S_P_BOOLEAN,
    "GraceTime": S_P_UINT32,
    "Hidden": S_P_BOOLEAN,
    "LLN": S_P_BOOLEAN,
    "MaxCPUsPerNode": S_P_UINT32,
    "MaxCPUsPerSocket": S_P_UINT32,
    "MaxMemPerCPU": S_P_UINT64,
    "MaxMemPerNode": S_P_UINT64,
    "MaxTime": S_P_STRING,
    "MaxNodes": S_P_UINT32,
    "MinNodes": S_P_UINT32,
    "Nodes": S_P_STRING,
    "OverSubscribe": S_P_STRING,
    "OverTimeLimit": S_P_STRING,
    "PowerDownOnIdle": S_P_BOOLEAN,
    "PreemptMode": S_P_STRING,
    "Priority": S_P_UINT16,
    "PriorityJobFactor": S_P_UINT16,
    "PriorityTier": S_P_UINT16,
    "QOS": S_P_STRING,
    "RootOnly": S_P_BOOLEAN,
    "ReqResv": S_P_BOOLEAN,
    "ResumeTimeout": S_P_UINT16,
    "SelectTypeParameters": S_P_STRING,
    "Shared": S_P_STRING,
    "State": S_P_STRING,
    "SuspendTime": S_P_STRING,
    "SuspendTimeout": S_P_UINT16,
    "Topology": S_P_STRING,
    "TRESBillingWeights": S_P_STRING,
}

# From https://github.com/SchedMD/slurm/blob/slurm-<VERSION>/src/common/read_config.c
slurm_options = {
    "AccountingStorageBackupHost": S_P_STRING,
    "AccountingStorageEnforce": S_P_STRING,
    "AccountingStorageExternalHost": S_P_STRING,
    "AccountingStorageHost": S_P_STRING,
    "AccountingStorageParameters": S_P_STRING,
    "AccountingStoragePass": S_P_STRING,
    "AccountingStoragePort": S_P_UINT16,
    "AccountingStorageTRES": S_P_STRING,
    "AccountingStorageType": S_P_STRING,
    # {"AccountingStorageUser": S_P_STRING, _defunct_option,
    "AccountingStoreFlags": S_P_STRING,
    "AccountingStoreJobComment": S_P_BOOLEAN,
    "AcctGatherEnergyType": S_P_STRING,
    "AcctGatherFilesystemType": S_P_STRING,
    "AcctGatherInfinibandType": S_P_STRING,
    "AcctGatherInterconnectType": S_P_STRING,
    "AcctGatherNodeFreq": S_P_UINT16,
    "AcctGatherProfileType": S_P_STRING,
    "AllowSpecResourcesUsage": S_P_BOOLEAN,
    "AuthAltParameters": S_P_STRING,
    "AuthAltTypes": S_P_STRING,
    "AuthInfo": S_P_STRING,
    "AuthType": S_P_STRING,
    "BackupAddr": S_P_STRING,
    "BackupController": S_P_STRING,
    "BatchStartTimeout": S_P_UINT16,
    "BcastExclude": S_P_STRING,
    "BcastParameters": S_P_STRING,
    "BurstBufferParameters": S_P_STRING,
    "BurstBufferType": S_P_STRING,
    "CertgenType": S_P_STRING,
    "CertgenParameters": S_P_STRING,
    "CertmgrType": S_P_STRING,
    "CertmgrParameters": S_P_STRING,
    "CliFilterParameters": S_P_STRING,
    "CliFilterPlugins": S_P_STRING,
    "ClusterName": S_P_STRING,
    "CommunicationParameters": S_P_STRING,
    "CompleteWait": S_P_UINT16,
    "ControlAddr": S_P_STRING,
    "ControlMachine": S_P_STRING,
    # {"CoreSpecPlugin": S_P_STRING, _defunct_option,
    "CpuFreqDef": S_P_STRING,
    "CpuFreqGovernors": S_P_STRING,
    "CredType": S_P_STRING,
    "CryptoType": S_P_STRING,
    "DataParserParameters": S_P_STRING,
    "DebugFlags": S_P_STRING,
    "DefCPUPerGPU": S_P_UINT64,
    "DefMemPerCPU": S_P_UINT64,
    "DefMemPerGPU": S_P_UINT64,
    "DefMemPerNode": S_P_UINT64,
    "DependencyParameters": S_P_STRING,
    "DisableRootJobs": S_P_BOOLEAN,
    "EioTimeout": S_P_UINT16,
    "EnforcePartLimits": S_P_STRING,
    "Epilog": S_P_ARRAY,
    "EpilogMsgTime": S_P_UINT32,
    "EpilogSlurmctld": S_P_ARRAY,
    "EpilogTimeout": S_P_UINT16,
    # {"ExtSensorsFreq": S_P_UINT16, _defunct_option,
    # {"ExtSensorsType": S_P_STRING, _defunct_option,
    "FairShareDampeningFactor": S_P_UINT16,
    "FastSchedule": S_P_UINT16,
    "FederationParameters": S_P_STRING,
    "FirstJobId": S_P_UINT32,
    # {"GetEnvTimeout": S_P_UINT16, _defunct_option,
    "GpuFreqDef": S_P_STRING,
    "GresTypes": S_P_STRING,
    "GroupUpdateForce": S_P_UINT16,
    "GroupUpdateTime": S_P_UINT16,
    "HashPlugin": S_P_STRING,
    "HealthCheckInterval": S_P_UINT16,
    "HealthCheckNodeState": S_P_STRING,
    "HealthCheckProgram": S_P_STRING,
    "HttpParserType": S_P_STRING,
    "InactiveLimit": S_P_UINT16,
    "InteractiveStepOptions": S_P_STRING,
    "JobAcctGatherFrequency": S_P_STRING,
    "JobAcctGatherParams": S_P_STRING,
    "JobAcctGatherType": S_P_STRING,
    "JobCompHost": S_P_STRING,
    "JobCompLoc": S_P_STRING,
    "JobCompParams": S_P_STRING,
    "JobCompPass": S_P_STRING,
    "JobCompPassScript": S_P_STRING,
    "JobCompPort": S_P_UINT32,
    "JobCompType": S_P_STRING,
    "JobCompUser": S_P_STRING,
    "JobContainerType": S_P_STRING,
    # {"JobCredentialPrivateKey": S_P_STRING, _defunct_option,
    # {"JobCredentialPublicCertificate": S_P_STRING, _defunct_option,
    "JobFileAppend": S_P_UINT16,
    "JobRequeue": S_P_UINT16,
    "JobSubmitPlugins": S_P_STRING,
    "KeepAliveTime": S_P_UINT32,
    "KillOnBadExit": S_P_UINT16,
    "KillWait": S_P_UINT16,
    "LaunchParameters": S_P_STRING,
    "LaunchType": S_P_STRING,
    "Licenses": S_P_STRING,
    "LogTimeFormat": S_P_STRING,
    "MailDomain": S_P_STRING,
    "MailProg": S_P_STRING,
    "MaxArraySize": S_P_UINT32,
    "MaxBatchRequeue": S_P_UINT32,
    "MaxDBDMsgs": S_P_UINT32,
    "MaxJobCount": S_P_UINT32,
    "MaxJobId": S_P_UINT32,
    "MaxMemPerCPU": S_P_UINT64,
    "MaxMemPerNode": S_P_UINT64,
    "MaxNodeCount": S_P_UINT32,
    "MaxStepCount": S_P_UINT32,
    "MaxTasksPerNode": S_P_UINT16,
    "MCSParameters": S_P_STRING,
    "MCSPlugin": S_P_STRING,
    "MessageTimeout": S_P_UINT16,
    "MetricsType": S_P_STRING,
    "MinJobAge": S_P_UINT32,
    "MpiDefault": S_P_STRING,
    "MpiParams": S_P_STRING,
    "NamespaceType": S_P_STRING,
    "NodeFeaturesPlugins": S_P_STRING,
    "OverTimeLimit": S_P_UINT16,
    "PluginDir": S_P_STRING,
    "PlugStackConfig": S_P_STRING,
    # {"PowerParameters": S_P_STRING, _defunct_option,
    # {"PowerPlugin": S_P_STRING, _defunct_option,
    "PreemptExemptTime": S_P_STRING,
    "PreemptMode": S_P_STRING,
    "PreemptParameters": S_P_STRING,
    "PreemptType": S_P_STRING,
    "PrEpParameters": S_P_STRING,
    "PrEpPlugins": S_P_STRING,
    "PriorityCalcPeriod": S_P_STRING,
    "PriorityDecayHalfLife": S_P_STRING,
    "PriorityFavorSmall": S_P_BOOLEAN,
    "PriorityFlags": S_P_STRING,
    "PriorityMaxAge": S_P_STRING,
    "PriorityParameters": S_P_STRING,
    "PrioritySiteFactorParameters": S_P_STRING,
    "PrioritySiteFactorPlugin": S_P_STRING,
    "PriorityType": S_P_STRING,
    "PriorityUsageResetPeriod": S_P_STRING,
    "PriorityWeightAge": S_P_UINT32,
    "PriorityWeightAssoc": S_P_UINT32,
    "PriorityWeightFairshare": S_P_UINT32,
    "PriorityWeightJobSize": S_P_UINT32,
    "PriorityWeightPartition": S_P_UINT32,
    "PriorityWeightQOS": S_P_UINT32,
    "PriorityWeightTRES": S_P_STRING,
    "PrivateData": S_P_STRING,
    "ProctrackType": S_P_STRING,
    "Prolog": S_P_ARRAY,
    "PrologEpilogTimeout": S_P_UINT16,
    "PrologFlags": S_P_STRING,
    "PrologSlurmctld": S_P_ARRAY,
    "PrologTimeout": S_P_UINT16,
    "PropagatePrioProcess": S_P_UINT16,
    "PropagateResourceLimits": S_P_STRING,
    "PropagateResourceLimitsExcept": S_P_STRING,
    "RebootProgram": S_P_STRING,
    "ReconfigFlags": S_P_STRING,
    "RequeueExit": S_P_STRING,
    "RequeueExitHold": S_P_STRING,
    "ResumeFailProgram": S_P_STRING,
    "ResumeProgram": S_P_STRING,
    "ResumeRate": S_P_UINT16,
    "ResumeTimeout": S_P_UINT16,
    "ResvEpilog": S_P_STRING,
    "ResvOverRun": S_P_UINT16,
    "ResvProlog": S_P_STRING,
    "ReturnToService": S_P_UINT16,
    "RoutePlugin": S_P_STRING,
    "SallocDefaultCommand": S_P_STRING,
    "SbcastParameters": S_P_STRING,
    "SchedulerParameters": S_P_STRING,
    "SchedulerTimeSlice": S_P_UINT16,
    "SchedulerType": S_P_STRING,
    "ScronParameters": S_P_STRING,
    "SelectType": S_P_STRING,
    "SelectTypeParameters": S_P_STRING,
    "SlurmctldAddr": S_P_STRING,
    "SlurmctldDebug": S_P_STRING,
    "SlurmctldLogFile": S_P_STRING,
    "SlurmctldParameters": S_P_STRING,
    "SlurmctldPidFile": S_P_STRING,
    "SlurmctldPort": S_P_STRING,
    "SlurmctldPrimaryOffProg": S_P_STRING,
    "SlurmctldPrimaryOnProg": S_P_STRING,
    "SlurmctldSyslogDebug": S_P_STRING,
    "SlurmctldTimeout": S_P_UINT16,
    "SlurmdDebug": S_P_STRING,
    "SlurmdLogFile": S_P_STRING,
    "SlurmdParameters": S_P_STRING,
    "SlurmdPidFile": S_P_STRING,
    "SlurmdPort": S_P_UINT32,
    "SlurmdSpoolDir": S_P_STRING,
    "SlurmdSyslogDebug": S_P_STRING,
    "SlurmdTimeout": S_P_UINT16,
    "SlurmdUser": S_P_STRING,
    "SlurmSchedLogFile": S_P_STRING,
    "SlurmSchedLogLevel": S_P_UINT16,
    "SlurmUser": S_P_STRING,
    "SrunEpilog": S_P_STRING,
    "SrunPortRange": S_P_STRING,
    "SrunProlog": S_P_STRING,
    "StateSaveLocation": S_P_STRING,
    "SuspendExcNodes": S_P_STRING,
    "SuspendExcParts": S_P_STRING,
    "SuspendExcStates": S_P_STRING,
    "SuspendProgram": S_P_STRING,
    "SuspendRate": S_P_UINT16,
    "SuspendTime": S_P_STRING,
    "SuspendTimeout": S_P_UINT16,
    "SwitchParameters": S_P_STRING,
    "SwitchType": S_P_STRING,
    "TaskEpilog": S_P_STRING,
    "TaskPlugin": S_P_STRING,
    "TaskPluginParam": S_P_STRING,
    "TaskProlog": S_P_STRING,
    "TCPTimeout": S_P_UINT16,
    "TLSParameters": S_P_STRING,
    "TLSType": S_P_STRING,
    "TmpFS": S_P_STRING,
    "TopologyParam": S_P_STRING,
    "TopologyPlugin": S_P_STRING,
    "TrackWCKey": S_P_BOOLEAN,
    "TreeWidth": S_P_UINT16,
    "UnkillableStepProgram": S_P_STRING,
    "UnkillableStepTimeout": S_P_UINT16,
    "UrlParserType": S_P_STRING,
    "UsePAM": S_P_BOOLEAN,
    "VSizeFactor": S_P_UINT16,
    "WaitTime": S_P_UINT16,
    "X11Parameters": S_P_STRING,
    "DownNodes": S_P_ARRAY,
    "NodeName": S_P_ARRAY,
    "NodeSet": S_P_ARRAY,
    "PartitionName": S_P_ARRAY,
    "SlurmctldHost": S_P_ARRAY,
}

# From https://github.com/SchedMD/slurm/blob/slurm-<VERSION>/src/slurmdbd/read_config.c
slurmdbd_options = {
    "AllowNoDefAcct": S_P_BOOLEAN,
    "AllResourcesAbsolute": S_P_BOOLEAN,
    "ArchiveDir": S_P_STRING,
    "ArchiveEvents": S_P_BOOLEAN,
    "ArchiveJobs": S_P_BOOLEAN,
    "ArchiveResvs": S_P_BOOLEAN,
    "ArchiveScript": S_P_STRING,
    "ArchiveSteps": S_P_BOOLEAN,
    "ArchiveSuspend": S_P_BOOLEAN,
    "ArchiveTXN": S_P_BOOLEAN,
    "ArchiveUsage": S_P_BOOLEAN,
    "AuthAltTypes": S_P_STRING,
    "AuthAltParameters": S_P_STRING,
    "AuthInfo": S_P_STRING,
    "AuthType": S_P_STRING,
    "CommitDelay": S_P_UINT16,
    "CommunicationParameters": S_P_STRING,
    "DbdAddr": S_P_STRING,
    "DbdBackupHost": S_P_STRING,
    "DbdHost": S_P_STRING,
    "DbdPort": S_P_UINT16,
    "DebugFlags": S_P_STRING,
    "DebugLevel": S_P_STRING,
    "DebugLevelSyslog": S_P_STRING,
    "DefaultQOS": S_P_STRING,
    "DisableCoordDBD": S_P_BOOLEAN,
    "DisableArchiveCommands": S_P_BOOLEAN,
    "HashPlugin": S_P_STRING,
    "JobPurge": S_P_UINT32,
    "LogFile": S_P_STRING,
    "LogTimeFormat": S_P_STRING,
    "MaxPurgeLimit": S_P_UINT32,
    "MaxQueryTimeRange": S_P_STRING,
    "MessageTimeout": S_P_UINT16,
    "Parameters": S_P_STRING,
    "PidFile": S_P_STRING,
    "PluginDir": S_P_STRING,
    "PrivateData": S_P_STRING,
    "PurgeEventAfter": S_P_STRING,
    "PurgeJobAfter": S_P_STRING,
    "PurgeResvAfter": S_P_STRING,
    "PurgeStepAfter": S_P_STRING,
    "PurgeSuspendAfter": S_P_STRING,
    "PurgeTXNAfter": S_P_STRING,
    "PurgeUsageAfter": S_P_STRING,
    "PurgeEventMonths": S_P_UINT32,
    "PurgeJobMonths": S_P_UINT32,
    "PurgeStepMonths": S_P_UINT32,
    "PurgeSuspendMonths": S_P_UINT32,
    "PurgeTXNMonths": S_P_UINT32,
    "PurgeUsageMonths": S_P_UINT32,
    "SlurmUser": S_P_STRING,
    "StepPurge": S_P_UINT32,
    "StorageBackupHost": S_P_STRING,
    "StorageHost": S_P_STRING,
    "StorageLoc": S_P_STRING,
    "StorageParameters": S_P_STRING,
    "StoragePass": S_P_STRING,
    "StoragePassScript": S_P_STRING,
    "StoragePort": S_P_UINT16,
    "StorageType": S_P_STRING,
    "StorageUser": S_P_STRING,
    "TCPTimeout": S_P_UINT16,
    "TLSParameters": S_P_STRING,
    "TLSType": S_P_STRING,
    "TrackWCKey": S_P_BOOLEAN,
    "TrackSlurmctldDown": S_P_BOOLEAN
}

# From https://github.com/SchedMD/slurm/blob/slurm-<VERSION>/src/interfaces/cgroup.c#L332
cgroup_options = {
    "CgroupAutomount": S_P_BOOLEAN,
    "CgroupMountpoint": S_P_STRING,
    "CgroupSlice": S_P_STRING,
    "ConstrainCores": S_P_BOOLEAN,
    "ConstrainRAMSpace": S_P_BOOLEAN,
    "AllowedRAMSpace": S_P_FLOAT,
    "MaxRAMPercent": S_P_FLOAT,
    "MinRAMSpace": S_P_UINT64,
    "ConstrainSwapSpace": S_P_BOOLEAN,
    "AllowedSwapSpace": S_P_FLOAT,
    "MaxSwapPercent": S_P_FLOAT,
    "MemoryLimitEnforcement": S_P_BOOLEAN,
    "MemoryLimitThreshold": S_P_FLOAT,
    "ConstrainDevices": S_P_BOOLEAN,
    "AllowedDevicesFile": S_P_STRING,
    "MemorySwappiness": S_P_UINT64,
    "CgroupPlugin": S_P_STRING,
    "IgnoreSystemd": S_P_BOOLEAN,
    "IgnoreSystemdOnFailure": S_P_BOOLEAN,
    "EnableControllers": S_P_BOOLEAN,
    "EnableExtraControllers": S_P_STRING,
    "SignalChildrenProcesses": S_P_BOOLEAN,
    "SystemdTimeout": S_P_UINT64
}

# From https://github.com/SchedMD/slurm/blob/slurm-<VERSION>/src/plugins/mpi/pmix/mpi_pmix.c#L83
mpi_options = {
	"PMIxCliTmpDirBase": S_P_STRING,
	"PMIxCollFence": S_P_STRING,
	"PMIxDebug": S_P_UINT32,
	"PMIxDirectConn": S_P_BOOLEAN,
	"PMIxDirectConnEarly": S_P_BOOLEAN,
	"PMIxDirectConnUCX": S_P_BOOLEAN,
	"PMIxDirectSameArch": S_P_BOOLEAN,
	"PMIxEnv": S_P_STRING,
	"PMIxFenceBarrier": S_P_BOOLEAN,
	"PMIxNetDevicesUCX": S_P_STRING,
	"PMIxShareServerTopology": S_P_BOOLEAN,
	"PMIxTimeout": S_P_UINT32,
	"PMIxTlsUCX": S_P_STRING
}

# From https://github.com/SchedMD/slurm/blob/slurm-<VERSION>s/src/interfaces/gres.c#L101C40-L116C2
gres_options = {
	"AutoDetect": S_P_STRING,
	"Count": S_P_STRING,	# Number of Gres available */
	"CPUs" : S_P_STRING,	# CPUs to bind to Gres resource
	"Cores": S_P_STRING,	# Cores to bind to Gres resource */
	"File":  S_P_STRING,	# Path to Gres device */
	"Files": S_P_STRING,	# Path to Gres device */
	"Flags": S_P_STRING,	# GRES Flags */
	"Link":  S_P_STRING,	# Communication link IDs */
	"Links": S_P_STRING,	# Communication link IDs */
	"MultipleFiles": S_P_STRING, # list of GRES device files */
	"Name":  S_P_STRING,	# Gres name */
	"Type":  S_P_STRING	# Gres type (e.g. model name) */
}

all_confs = {
    "slurm": slurm_options,
    "slurmdbd": slurmdbd_options,
    "cgroup": cgroup_options,
    "mpi": mpi_options,
    # "gres": gres_options,
    # GRES can have different combinations, hence excluded
    # https://slurm.schedmd.com/gres.conf.html#SECTION_EXAMPLES
    "PartitionName": partition_options,
    "NodeName": nodename_options,
    "DownNodes": downnodes_options,
    "NodeSet": nodeset_options
}

_HOSTLIST_RE = re.compile(r'^(?P<prefix>[^\[\]]*)\[(?P<inner>[^\[\]]+)\](?P<suffix>.*)$')


def expand_hostlist(expr):
    """
    Expand simple Slurm-style hostlist expressions, e.g.:
      dev[0-2,5,10-12] -> [dev0, dev1, dev2, dev5, dev10, dev11, dev12]
    If no brackets, returns [expr].
    """
    m = _HOSTLIST_RE.match(expr)
    if not m:
        return [expr]

    prefix = m.group("prefix")
    inner = m.group("inner")
    suffix = m.group("suffix")

    hosts = []
    for part in inner.split(','):
        part = part.strip()
        if '-' in part:
            start_s, end_s = part.split('-', 1)
            width = max(len(start_s), len(end_s))
            start = int(start_s)
            end = int(end_s)
            step = 1 if end >= start else -1
            for i in range(start, end + step, step):
                hosts.append(f"{prefix}{str(i).zfill(width)}{suffix}")
        else:
            # single index
            width = len(part)
            i = int(part)
            hosts.append(f"{prefix}{str(i).zfill(width)}{suffix}")
    return hosts
