#!/bin/bash
pid=$(ps | grep http | awk '{print $1}')
pid=$(ps | grep memcheck | awk '{print $1 }')
if [ "$pid" == "" ]
then 
	echo "no pid"
else
	kill $pid
fi
