#!/bin/bash
usage() { echo "Usage: $0 [-d dev] [-p repeate] [-n num_th] [-t type p|sw]" 1>&2; exit 1; }


trap ctrl_c SIGINT

function ctrl_c() 
{
    trap '' SIGINT
    echo "CTRL-C exiting ..."
    killall -KILL badblocks

    for ((i=0; i<$num_th; i++)); do
            if [ -f ./bad_block_${i} ] && ! [ -s ./bad_block_${i} ] ; then
                    rm ./bad_block_${i}
            fi
    done

    exit 0
}

function parallel_test()
{
    echo "running parallel test"
    step=$(($dev_sz / $num_th - 1))

    for ((i=0; i<$num_th; i++)); do

            tend=$(($tstart + $step))
            
            echo "checking blocks" $tstart "to" $tend

            badblocks -w ${dev} -o ./bad_block_${i} -p $rep $tend $tstart -b $dev_pbs 2>/dev/null &

            tstart=$(($tend + 1))
    done        
}


function sweep_test()
{
    echo "running sweep test"
    
     step=$(($dev_sz / $num_th - 1))
    
    for ((i=0; i<$num_th; i++)); do

            tend=$(($tstart + $step))
            
            echo "checking blocks" $tstart "to" $tend

            badblocks -wsv ${dev} -o ./bad_block_${i} -p $rep $tend $tstart -b $dev_pbs

            tstart=$(($tend + 1))
    done 
}

num_th=1
start=0
end=0
test_type="lp"
rep=1000000

while getopts d:s:e:n:t:r: flag; do
    case $flag in
    d)
            dev=$OPTARG;;
    s)
            start=$OPTARG;;
    e)
            end=$OPTARG;;
    n)
            num_th=$OPTARG;;
    t)
            test_type=$OPTARG;;
    r)
            rep=$OPTARG;;
    ?)
            usage;;
    esac
done

shift $(( OPTIND - 1 ));

if ! [ -b "$dev" ] ; then
    echo $dev "is not a block device"
    exit -1
fi

dev_pbs=$(blockdev --getpbsz $dev)
dev_sz=$(blockdev --getsz $dev)


echo $dev, $dev_pbs, $dev_sz

tstart=0
end=$(($dev_sz - 1))

case $test_type in
    "p")
        parallel_test;;
    "sw")
        sweep_test;;
esac
    
echo "waiting for bad blocks"

while true
do
    for ((i=0; i<$num_th; i++)); do                
        if [ -s ./bad_block_${i} ]; then
                echo "file has bad blocks", ./bad_block_${i}
                cat ./bad_block_${i}
        fi
    done
    sleep 1
done
