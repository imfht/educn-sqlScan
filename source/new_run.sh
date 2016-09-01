while :
do
	target_name=$(find . -size 0c )
	echo $target_name
	for i in $target_name
	do
		python get_subDomain.py -u $(echo $i| awk -F "_" '{print $1}') -c -w
		sleep 5
                echo $data"加入了一个文件"$$i
	done
echo "waiting..."
sleep 20
done
