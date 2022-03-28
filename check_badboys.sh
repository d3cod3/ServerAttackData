#!/bin/sh

# for local access
tempscriptfolder="."

# for absolute access ( from crontab, for example )
#tempscriptfolder="ABSOLUTE_PATH_TO_THIS_SCRIPT_FOLDER"

> $tempscriptfolder/badboys.txt

# search for attackers ip in failtoban log
cat /var/log/fail2ban.log | egrep -o '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort | uniq -c | sort -rn | awk '{print $1 " " $2}' | grep -v '127.0.0.1' >> $tempscriptfolder/badboys.txt

logwatch --detail High --service http > $tempscriptfolder/logwatch.temp

cat $tempscriptfolder/logwatch.temp | egrep -o '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort | uniq -c | sort -rn | awk '{print $1 " " $2}' >> $tempscriptfolder/badboys.txt

# scalp over nginx access log for attackers
python3 $tempscriptfolder/scalp-0.4.py --stdout -e -l /var/log/nginx/access.log -f $tempscriptfolder/scalper_filter.xml | egrep -o '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort | uniq -c | sort -rn | awk '{print $1 " " $2}' >> $tempscriptfolder/badboys.txt

# create new temp data output file
> $tempscriptfolder/badboys.json.temp

echo { >> $tempscriptfolder/badboys.json.temp
echo \"type\": \"FeatureCollection\", >> $tempscriptfolder/badboys.json.temp

# create random IP for off-grid server ( this box )
myIP=`php $tempscriptfolder/randomIP.php`
myLoc=`curl -s https://ipinfo.io/$myIP | grep loc | awk '{print $2}' | sed 's/\"//g' | sed 's/,$//'`

if [ -z $myLoc ]
then
        randLAT=$((`shuf -i1-180 -n1` - 90))
        randLNG=$((`shuf -i1-360 -n1` - 180))
        randLF1=`shuf -i1-9999 -n1`
        randLF2=`shuf -i1-9999 -n1`
        myLoc=$randLAT.$randLF1,$randLNG.$randLF2
fi


echo \"servers\": [{\"type\": \"Server\",\"properties\": {\"IP\": \"$myIP\"},\"geometry\": {\"type\": \"Point\",\"coordinates\": [$myLoc]} }], >> $tempscriptfolder/badboys.json.temp

echo \"features\": [ >> $tempscriptfolder/badboys.json.temp

numlines=`cat $tempscriptfolder/badboys.txt | wc -l`
counter=1

# extract data from attackers IPs
cat $tempscriptfolder/badboys.txt | while read line
do

hostIP=`echo $line | awk '{print $2}'`
traceroute $hostIP | egrep -o '([0-9]{1,3}\.){3}[0-9]{1,3}' | uniq -c | awk '{print $2}' | tail -n +3 > $tempscriptfolder/traceroutes/$hostIP.txt
hostIntensity=`echo $line | awk '{print $1}'`
domain=`host $hostIP | awk '{print $5}' | sed 's/.$//'`
company=`whois $hostIP | grep "org-name" | awk '{print $2}'`
loc=`curl -s https://ipinfo.io/$hostIP | grep loc | awk '{print $2}' | sed 's/\"//g' | sed 's/,$//' | sed 's/[a-zA-Z]//g;/^$/d' | sed 's/[\t ]//g;/^$/d'`


oct1=`echo $hostIP | tr "." " " | awk '{ print $1 }'`
oct2=`echo $hostIP | tr "." " " | awk '{ print $2 }'`
oct3=`echo $hostIP | tr "." " " | awk '{ print $3 }'`
oct4=`echo $hostIP | tr "." " " | awk '{ print $4 }'`

istor=`dig $oct4.$oct3.$oct2.$oct1.6667.4.3.2.1.ip-port.exitlist.torproject.org | grep status: | awk '{print $6}' | sed 's/,$//'`

if [ $domain != "undefined.hostname.localhost" ]
then
	if [ $loc = ${loc%[[:space:]]*} ]
	then
		echo {\"type\": \"Feature\", >> $tempscriptfolder/badboys.json.temp

  		if [ $istor = "NOERROR" ]
  		then
			if [ $domain = "recor" ]
			then
				echo \"properties\": {\"IP\": \"$hostIP\",\"Domain\": \"arpa has no PTR record\",\"Intensity\": \"$hostIntensity\",\"TORRELAY\": \"YES\",\"Company\": \"$company\"}, >> $tempscriptfolder/badboys.json.temp
			else
				echo \"properties\": {\"IP\": \"$hostIP\",\"Domain\": \"$domain\",\"Intensity\": \"$hostIntensity\",\"TORRELAY\": \"YES\",\"Company\": \"$company\"}, >> $tempscriptfolder/badboys.json.temp
			fi
  		else
			if [ $domain = "recor" ]
			then
				echo \"properties\": {\"IP\": \"$hostIP\",\"Domain\": \"arpa has no PTR record\",\"Intensity\": \"$hostIntensity\",\"TORRELAY\": \"NO\",\"Company\": \"$company\"}, >> $tempscriptfolder/badboys.json.temp
			else
				echo \"properties\": {\"IP\": \"$hostIP\",\"Domain\": \"$domain\",\"Intensity\": \"$hostIntensity\",\"TORRELAY\": \"NO\",\"Company\": \"$company\"}, >> $tempscriptfolder/badboys.json.temp
			fi
  		fi
        	echo \"geometry\": {\"type\": \"Point\",\"coordinates\": [$loc]}, >> $tempscriptfolder/badboys.json.temp

		echo \"traceroute\": {\"type\": \"MultiPoint\",\"coordinates\": [ >> $tempscriptfolder/badboys.json.temp

		chainLines=`cat $tempscriptfolder/traceroutes/$hostIP.txt | wc -l`
		chainCounter=1

		cat $tempscriptfolder/traceroutes/$hostIP.txt | while read tr_line
		do
			chainIP=`echo $tr_line | awk '{print $1}'`
			chainLoc=`curl -s https://ipinfo.io/$chainIP | grep loc | awk '{print $2}' | sed 's/\"//g' | sed 's/,$//' | sed 's/[a-zA-Z]//g;/^$/d' | sed 's/[\t ]//g;/^$/d'`

			if [ -z $chainLoc ]
			then
				# do nothing
				chainLoc=""
			else

				if [ $chainCounter -eq $chainLines  ]
				then
					if [ $chainLoc != *".."* ]
					then
						echo [$chainLoc] >> $tempscriptfolder/badboys.json.temp
					else
						echo [] >> $tempscriptfolder/badboys.json.temp
					fi
				else
					if [ $chainLoc != *".."* ]
					then
						echo [$chainLoc], >> $tempscriptfolder/badboys.json.temp
					fi
				fi

			fi

			chainCounter=$((chainCounter+1))
		done

		echo ]} >> $tempscriptfolder/badboys.json.temp

		if [ $counter -eq $numlines ]
  		then
        		echo } >> $tempscriptfolder/badboys.json.temp
  		else
        		echo }, >> $tempscriptfolder/badboys.json.temp
  		fi
	fi

fi

counter=$((counter+1))

done

echo ]} >> $tempscriptfolder/badboys.json.temp

#save history log
filedate=`echo $(date '+_%d_%m_%Y')`
cp $tempscriptfolder/badboys.json.temp $tempscriptfolder/history_log/badboys$filedate.json
