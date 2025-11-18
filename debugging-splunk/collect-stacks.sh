#!/usr/bin/env bash

SPLUNK_HOME=${SPLUNK_HOME:-/opt/splunk}

set -e
set -u
#set -x

platform="$(uname)"
if [[ "$platform" != 'Linux' ]]; then
    echo "ERROR: This script is only tested on Linux, \`uname\` says this is '$platform'" >&2
    exit 1
fi

function usage()
{
     echo "Usage: $0 [OPTION]"
     echo "Collect stack dumps for splunk support. A good number of samples is in the hundreds, preferably 1000."
     echo
     echo "  -b, --batch               Non-interactive mode, doesn't ask questions."
     echo "  -c, --continuous          Collect data continuously, keeping only the latest <samples>"
     echo "                            dump files."
     echo "  -d, --docker=CONTAINER_ID Collect data from inside docker container CONTAINER_ID."
     echo "                            Remember you must use the PID you see inside the container."
     echo "  -f, --freeze              Freeze process during data collection to obtain consistent snapshots."
     echo "                            This is very disruptive, avoid if possible."
     echo "  -h, --help                Print this message."
     echo "  -i, --interval=INTERVAL   Interval between samples, in seconds. Default is 0.5."
     echo "  -o, --outdir=PATH         Output directory. Default is '/tmp/splunk'"
     echo "  -p, --pid=PID             PID of process. Default is to use main splunk process if"
     echo "                            SPLUNK_HOME is set or splunk is under '/opt/splunk'"
     echo "  -q, --quiet               Silent mode, output no messages after parameter"
     echo "                            confirmation (or none at all in batch mode)."
     echo "  -r, --rest                Use Splunk's own '/services/server/pstacks' endpoint instead of an"
     echo "                            external tool like eu-stack for data collection. This will require"
     echo "                            entering valid username/password credentials for a user with the"
     echo "                            'request_pstacks' capability."
     echo "  -s, --samples=COUNT       Number of samples. Aim for more than 100. Default 1000."
}

#
# Handing command-line arguments
#
batch=0
continuous=0
container=''
freeze=0
interval=0.5
outdir='/tmp/splunk'
pid=''
rest=0
quiet=0
samples=1000
while [ "$#" != "0" ] ; do
    case "$1" in
        -b|--batch)      batch=1;;
        -c|--continuous) continuous=1;;
        -d|--docker)
            shift
            container="$1"
            ;;
        -f|--freeze)   freeze=1;;
        -h|-\?|--help)   usage; exit;;
        --interval=*)    interval=${1#*=};;
        -i|--interval)
            shift
            if [ "$#" != "0" ]; then interval="$1"; else interval=''; fi
            ;;
        --outdir=*) outdir=${1#*=};;
        -o|--outdir)
            shift
            if [ "$#" != "0" ]; then outdir="$1"; else outdir=''; fi
            ;;
        --pid=*) pid=${1#*=};;
        -p|--pid)
            shift
            if [ "$#" != "0" ]; then pid="$1"; else pid=''; fi
            ;;
        -q|--quiet) quiet=1;;
        -r|--rest)  rest=1;;
        --samples=*) samples=${1#*=};;
        -s|--samples)
            shift
            if [ "$#" != "0" ]; then samples="$1"; else samples=''; fi
            ;;
        *)
            echo "ERROR: invalid option '$1'" >&2
            exit 1
            ;;
    esac

    if [ "$#" != "0" ]; then shift; fi
done

if [ "$rest" == "1" ]; then
    if [ ! -x "$SPLUNK_HOME/bin/splunk" ]; then
        echo "ERROR: can't execute $SPLUNK_HOME/bin/splunk" >&2
        exit 1
    fi
    echo "Please provide credentials with the request_pstacks capability:"
    if ! "$SPLUNK_HOME/bin/splunk" login; then
        echo "ERROR: can't proceed without valid credentials, aborting" >&2
        exit 1
    fi
fi

nsenter_prefix=""
if ! [ -z "$container" ]; then
    set +e
    err="$(docker inspect --format {{.State.Pid}} "$container" 2>&1)"
    if [ "$?" != "0" ]; then
        echo "ERROR: invalid value for --docker option, are you sure your container ID is running? '$container': $err" >&2
        exit 1
    fi
    nsenter_prefix="nsenter --target $err --mount --pid"
fi

if ! [[ "$interval" =~ ^[0-9]*(|\.[0-9]*)$ && "$interval" =~ [1-9] ]]; then
    echo "ERROR: invalid value for --interval option, '$interval'" >&2
    exit 1
fi

function run() {
    if [ -z "$nsenter_prefix" ]; then
        eval "$@"
    else
        $nsenter_prefix bash -c "$*"
    fi
}

set +e
err="$(mkdir -p "$outdir" 2>&1)"
if [ "$?" != "0" ]; then
    echo "ERROR: invalid value for --outdir option, '$outdir': $err" >&2
    exit 1
fi
set -e

if [ -z "$pid" ]; then
    set +e
    pid="$(run head -n1 "$SPLUNK_HOME/var/run/splunk/splunkd.pid" 2>/dev/null)"
    set -e
fi
if [ -z "$pid" ]; then
    echo "ERROR: pid not specified and could not infer main splunkd server process id from SPLUNK_HOME='$SPLUNK_HOME'." >&2
    exit 1
fi
if [[ ! "$pid" =~ ^[1-9][0-9]*$ ]]; then
    echo "ERROR: pid must be a positive integer, not '$pid'." >&2
    exit 1
fi
set +e
err="$(run kill -0 $pid 2>&1)"
if [ "$?" != "0" ]; then
    echo "ERROR: not able to get data about PID $pid; wrong pid or missing sudo? Attempt to read returned '${err#*- }.'"
    exit 1
fi
[[ ! "$(run readlink -f /proc/$pid/exe)" =~ splunkd$ ]]
readonly isSplunkd=$?
set -e
if [[ ! $samples =~ ^[1-9][0-9]*$ ]]; then
    echo "ERROR: number of samples must be a positive integer, not '$samples'." >&2
    exit 1
fi

#
# Now check what we'll use for stack collection
#
set +e
cmd=(eu-stack -lip PID)
if [ "$rest" == "1" ]; then
    cmd=("$SPLUNK_HOME/bin/splunk" _internal call /services/server/pstacks -get:output_mode json)
elif [ "${FORCE_PSTACK:-0}" == "1" ]; then
    cmd=(pstack PID)
elif [ "${FORCE_GDB:-0}" == "1" ]; then
    cmd=(gdb -batch -n -ex "'thread apply all bt'" -p PID)
    echo "*******************"
    echo -e "WARNING: Use of GDB is being enforced because FORCE_GDB=$FORCE_GDB -- this is not recommended, please avoid if at all possible."
    echo "*******************"
fi
if ! run type ${cmd[0]} > /dev/null; then
    extra_help=''
    if [[ ${cmd[0]} == "eu-stack" ]]; then
        if [ -z "$nsenter_prefix" ]; then
            extra_help=" Please install the 'elfutils' package in your system."
        else
            extra_help=" Please install the 'elfutils' package by running:\n    docker exec $container bash -c 'sudo apt update && sudo apt install -y elfutils'."
        fi
    fi
    if [ -z "$nsenter_prefix" ]; then
        echo "ERROR: ${cmd[0]} is unavailable!$extra_help" >&2
    else
        echo -e "ERROR: ${cmd[0]} is unavailable in container with id=$container!$extra_help" >&2
    fi
    exit 7
fi
set -e

if [ "$batch" == "0" ]; then
    echo "Parameters:"
    echo "  SPLUNK_HOME='$SPLUNK_HOME'"
    echo "  --batch=$batch"
    echo "  --continuous=$continuous"
    echo "  --docker=$container"
    echo "  --interval=$interval"
    echo "  --outdir='$outdir'"
    echo "  --pid=$pid"
    echo "  --samples=$samples"
    echo

    if [[ $samples -lt 100 ]]; then
        read -p "Number of samples should really be at least 100 -- are you sure you want to continue? (y/n) " choice
    else
        read -p "Do you wish to continue? (y/n) " choice
    fi
    case "$choice" in
        y|Y ) echo;;
        * )   exit 0;;
    esac
fi

function printout() {
    if [ $quiet -eq 0 ]; then
        echo "$@"
    fi
}

function printstatus() {
    if [ $quiet -eq 0 ] || [ "$batch" == "0" ]; then
        printf "Completion status: % ${#2}d/$2\r" $1
    fi
}

function printerr() {
    if [ $quiet -eq 0 ]; then
        echo "$@" >&2
    fi
}

function timestamp() { date +'%Y-%m-%dT%Hh%Mm%Ss%Nns%z'; }

function collect_proc() {
    set +e
    run 'for d in /proc/'$pid' /proc/'$pid'/task/*; do
        lwp=$(basename "$d");
        echo "Thread LWP $lwp";
        cat "$d/'$1'";
    done'
    set -e
}

# If the user aborts the script midway through data collection, we still want
# zip up the results.
subprocesses=''
function wait_subprocesses_revive_pid() {
    # `wait` won't work because we use setsid for stack collection, so we
    # improvise in a very ugly way
    for proc in $subprocesses; do
        run "while [ -e /proc/$proc ]; do sleep 0.1; done"
    done

    if run [ -e /proc/$pid ] && run grep -q "[[:space:]]*State:[[:space:]]*[Tt]" "/proc/$pid/status" >/dev/null 2>&1; then
        kill -CONT $pid
    fi
}

function archive_on_abort() {
    trap '' SIGINT
    echo "** Trapped CTRL-C. Archiving partial results. Please wait. **"
    wait_subprocesses_revive_pid
    archive
}
trap archive_on_abort INT

# zip up the results
function archive() {
    local outroot="$(dirname "$outdir")"
    local outleaf="$(basename "$outdir")"
    local archive="$outdir.tar.xz"
    tar --remove-files -C "$outroot" -cJf "$archive" "$outleaf"
    printout "Stacks saved in $archive"
    if [ "$rest" == "1" ]; then
        "$SPLUNK_HOME/bin/splunk" logout
    fi
}

outdir="$outdir/stacks-${pid}-${HOSTNAME}-$(timestamp)"
mkdir -p "$outdir"

collect_proc "maps" >"$outdir/proc-maps.out" 2>"$outdir/proc-maps.err"

declare -a suffixes
for ((i=0; $i < $samples; i = $continuous ? ($i+1)%$samples : $i+1)); do
    if run [ ! -e /proc/$pid ]; then
        printerr $'\n'"Process with pid=$pid no longer available, terminating stack dump collection."
        break;
    fi
    printstatus $i $samples
    suffix="$(timestamp)"
    if [ "${suffixes[$i]+isset}" ]; then
        rm -f "$outdir"/*"${suffixes[$i]}".{out,err}
    fi
    suffixes[$i]=$suffix

    # collect application stack
    stackdump_fname="$outdir/stack-$suffix"
    if [ "$rest" != "1" ]; then
        # TODO: use quiet mode (-q) and use `eu-nm` to collect symbol location
        # for all libraries in /proc/<pid>/maps that are outside of $SPLUNK_HOME
        # that way collection for each dump should take ~50ms and we can resolve
        # all symbols at home -- kinda like jeprof does it
        cmd[${#cmd[@]}-1]=$pid
        if [ "$freeze" != "0" ]; then
            kill -STOP $pid
        fi
        # use setsid to isolate subprocess from signals (like SIGINT)
    fi
    run setsid "${cmd[@]}" >"$stackdump_fname.out" 2>"$stackdump_fname.err" &
    subprocesses=$!

    # collect /proc/<pid> information for all tasks
    for f in stack status; do
        fname="$outdir/proc-$f-$suffix"
        collect_proc "$f" >$fname.out 2>$fname.err &
    done
    wait

    # wait for application stack program to wrap up
    wait_subprocesses_revive_pid

    grep_cmd=(grep -v 'no matching address range\|No DWARF information\|No such process' "$stackdump_fname.err")
    if [ -s "$stackdump_fname.err" ] && "${grep_cmd[@]}" >/dev/null; then
        printout $'\n'"--- Possibly harmless STDERR from \`${cmd[*]}\`:"
        printout "$("${grep_cmd[@]}")"
    fi
    if ! grep -q "TID\|LWP\|services/server/pstacks" "$stackdump_fname.out" >/dev/null 2>&1; then
        printerr $'\n'"ERROR: latest stack dump ($stackdump_fname.out) doesn't contain any thread information! Please try running manually and check output:" >&2
        printerr "  ${cmd[*]}" >&2
        exit 1
    fi
    if [ "$isSplunkd" != "0" ] && ! grep -qi 'Thread.*main' "$stackdump_fname.out" >/dev/null 2>&1; then
        printerr $'\n'"ERROR: latest stack dump ($stackdump_fname.out) doesn't contain 'Thread's or 'main()' call, which is very unexpected for splunkd! Please try running manually and check output:" >&2
        printerr "  ${cmd[*]}" >&2
    fi

    if run [ ! -e /proc/$pid ]; then
        break;
    fi
    sleep $interval
done
printout

archive
