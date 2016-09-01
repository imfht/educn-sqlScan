while :
do
	target_name=$(find . -size 0c )
	echo $target_name
	for i in $(cat $1)
	do
		python get_subDomain.py -u $i -c -w
		sleep 5
	done
sleep 20
done
