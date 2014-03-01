#!/bin/sh
T=$1
TR=`pwd`
#for i in 1 2 3 4 5 6 99
for i in 2 3 4 5 99
do
    echo Testing No.$i
    cd $TR/$i
    sh ./run.sh $T
done
cd $TR
