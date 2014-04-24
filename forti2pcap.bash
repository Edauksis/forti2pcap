#!/bin/bash
# Convert Fortigate's '''diagnose sniffer packet any "host IP" 6 0 a''' output 2 pcap
# undebug - esteban@dauksis.com

F_IN=$1

for Interface in $(cat $F_IN | grep -E ^[0-9]\{4\}\-[0-9]\{2\}\-[0-9]\{2\} | awk '{ print $3 }' | sort | uniq)
do
	echo "Processing $F_IN.$Interface.pcap"
	cat $F_IN | sed -e /.*"$Interface".*/,/^.$/\!d | \
	sed -e 's/\ \([0-9a-fA-F]\{2\}\)\([0-9a-fA-F]\{2\}\)\ /\ \1\ \2\ /g' | \
	sed -e 's/\ \([0-9a-fA-F]\{2\}\)\([0-9a-fA-F]\{2\}\)\ /\ \1\ \2\ /g' | \
	sed -e 's/\ \([0-9a-fA-F]\{2\}\)\([0-9a-fA-F]\{2\}\)\t/\ \1\ \2\ \t/g' | \
	sed -e 's/^0x/00/' | \
	sed -e 's/\(^[0-9]\{4\}\-[0-9]\{2\}\-[0-9]\{2\}\ [0-9]\{2\}:[0-9]\{2\}:[0-9]\{2\}\.[0-9]\{6\}\ \).*/\1/' | \
	text2pcap -t "%Y-%m-%d %H:%M:%S." - $F_IN.$Interface.pcap 2>&1 | tail -1

done
echo -e "First packet: $(cat $F_IN | grep  -Eo ^[0-9]\{4\}\-[0-9]\{2\}\-[0-9]\{2\}\ [0-9]\{2\}:[0-9]\{2\}:[0-9]\{2\}\.[0-9]\{6\}\ | head -1)"
echo -e "Last packet: $(cat $F_IN | grep  -Eo ^[0-9]\{4\}\-[0-9]\{2\}\-[0-9]\{2\}\ [0-9]\{2\}:[0-9]\{2\}:[0-9]\{2\}\.[0-9]\{6\}\ | tail -1)\n"

