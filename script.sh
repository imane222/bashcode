#!/bin/bash
score="20" # [Abuse Confidence Score] to ban ip 
sleep_time_s=5 # sleep time in seconds

# Your abuseipdb APi key
api_key=12345667890abcd12345667890abcd12345667890abcd12345667890abcd12345667890abcd

#################################################################################################

# we need to run script with root permissions.
# to be able to change Firewall setting ,
if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi

# check if source file is empty or not exist .
if [ ! -e  source.txt ]; then
	touch source.txt
fi
if [ ! -s source.txt ]
  then 
  echo "File [source.txt] is empty "
  echo " Please add at least one log path ."
  echo " Example : /var/log/auth.log "
  exit
fi
if [ ! -e log.txt ]; then
	touch log.txt
fi
if [ ! -e banned_ip.txt ]; then  
	touch banned_ip.txt
fi
if [ ! -e  trusted_ip.txt ]; then
	touch trusted_ip.txt
fi
if [ ! -e  error.txt ]; then
	touch error.txt
fi


#################################################################################################
helpFunction()
{
   echo ""
   echo "Usage: "
   echo -e "\t-r run      :to run the script"
   echo -e "\t-t ip_adress : Added trusted IP"
   echo -e "\t-b ip_adress : Added banned IP"
   echo -e "\t-c ip_adress : Check IP"
   echo ""
   echo "Examples.: "
   echo -e "\t sudo ./script.sh -r run"
   echo -e "\t sudo ./script.sh -t 8.8.8.8"
   echo -e "\t sudo ./script.sh -c 192.168.1.200"
   exit 1 
}

while getopts "r:t:b:c:" opt
do
   case "$opt" in
	  r ) p_r="$OPTARG" ;;
	  t ) p_t="$OPTARG" ;;
	  b ) p_b="$OPTARG" ;;
	  c ) p_c="$OPTARG" ;;
          ? ) helpFunction ;; # run helpFunction in case parameter is non-existent
   esac
done


if [ -z "$p_r" ] && [ -z "$p_t" ] && [ -z "$p_b" ] && [ -z "$p_c" ]
then
   echo "Some the parameters are empty";
   helpFunction
fi

if [ ! -z "$p_t" ] 
then
	echo $p_t " Has been Added to Trusted list ."
	echo $p_t >> trusted_ip.txt
	exit 1
elif [ ! -z "$p_b" ] 
then
	echo $p_b " Has been Added to Banned list ."
	echo $p_b >> banned_ip.txt
	exit 1
elif [ ! -z "$p_c" ] 
then
	if  grep -Rq "$p_c" trusted_ip.txt ; then
		echo $p_c " Found in trusted_ip.txt  "
	elif  grep -Rq "$p_c" banned_ip.txt ; then
		echo $p_c " Found in banned_ip.txt "
	elif  grep -Rq "$p_c" log.txt ; then
		echo $p_c " Found in log.txt "
	else
		echo $p_c " Not Found"
	fi
	exit 1
fi



#####################################################################################################


while true
do
		###############################################
		input="source.txt"
		while read -r line
		do
				if  grep -Rq "can t access to the file : $line" error.txt 
					then 
					continue;
				else
					if [ ! -e $line ]; then
						echo  "can t access to the file : " $line 
						echo  "can t access to the file : " $line >> error.txt                
						continue;
					fi
				fi
				if [ "$line" = '' ]; then 
					continue;
				fi
				###############################################
		  	
				grep -E -o "([0-9]{1,3}[\.]){3}[0-9]{1,3}" $line | uniq | 
				while read -r ip ; do
					if  grep -Rq "$ip" log.txt ; then
						continue;
					else
						echo "New Ip : $ip From " $line
						echo "New Ip : $ip From " $line >> log.txt
					fi

					if  grep -Rq "$ip" trusted_ip.txt 
					  then 
						  continue;
					fi	  
									   
					IP2=$(curl -s -G 'https://api.abuseipdb.com/api/v2/check' --data-urlencode "ipAddress=$ip" -d maxAgeInDays=90 -d verbose -H "Key: $api_key" -H "Accept: application/json" | jq -r 		'.data.abuseConfidenceScore')
					
					if  (($IP2 > $score ))
					  then  
						 echo "[Action:Ban] Ip : $ip , Has hight Abuse_Confidence_Score " >> log.txt
						 iptables -A INPUT -s $ip -j DROP
						 echo $ip  >> banned_ip.txt                      
					fi		
					sleep 0.5
					
				done
				###############################################
		done < "$input"
		sleep $sleep_time_s
		###############################################
done


