#!/bin/sh

# test suite
# contricutor shall pass this test before making a patch (or pull request)

# TODO
# some of these tests should be merged into Joe's dm-test-suite

T=$1
TR=`pwd`
#for i in 1 2 3 4 5 6 99
for i in 2 3 4 5 99
do
    echo -----------------------------
    echo ------ testing no.$i -------
    echo -----------------------------

    cd $TR/$i
    sh ./run.sh $T

    # sleeping here 10 sec to wait for background cleanup
    # but this is too heuristic.
    # better to do more appropriate operation
    sleep 10
done
cd $TR
