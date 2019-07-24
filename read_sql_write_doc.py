import pymysql
import json
import sys
import time
import memory_profiler
# sql = "select * from probe_req where src_mac='%s'" %(mac_list)

hash_set = []

def data_filter(time1, time2):
	dl_time1 = time.strptime(time1, "%Y-%m-%d %X")
	dl_time2 = time.strptime(time2, "%Y-%m-%d %X")
	if (dl_time1 < dl_time2):
		return False
	if (dl_time1 > dl_time2):
		return True

def IsLocalMac(args):
    '''
    @args: string of mac ("00:00:00:00:00:01")
    @function: judge whether the least second bit in first octet is 1
                1 means local mac address
                0 means universal mac address
    @return: boolean
            true: the string of mac is random mac
            false: that isn't random mac
    '''
    split_res = args.split(':')
    try:
        if len(split_res)!= 6:
            raise Exception("mac string format is error!")
    except Exception as e:
        print (e)
        sys.exit()
    int_val = int('0x' + split_res[0], 16)
    bin_val = bin(int_val)
    flag = bin_val[-2]
    if flag == '1':
        return True
    else:
        return False

"""
search info of mac list 
"""
def search_info(cur, conn, mac_list, sql, query_t, choice):
	mac_cnt = {}
	mac_hash_dict = {}
	cnt = 0
	mac_list_dict = {}
	cur.execute(sql)
	while True:
		cnt = cnt + 1
		res = cur.fetchone()
		if not res:
			break
		mac = res[0]
		info = res[2]
		mac_time = res[1]
		if choice == 1:
			if mac in mac_list and data_filter(mac_time, query_t):
				print (mac, mac_time, str(res[3]), str(info))
				if mac not in list(mac_hash_dict.keys()):
					mac_hash_dict[mac] = []
					mac_hash_dict[mac].append(hash(info))
					mac_cnt[mac] = 1
				if mac not in list(mac_list_dict.keys()):
					mac_list_dict[mac] = []
					mac_list_dict[mac].append(info)
				if hash(info) not in mac_hash_dict[mac]:
					mac_list_dict[mac].append(info)
					mac_hash_dict[mac].append(hash(info))
					mac_cnt[mac] = mac_cnt[mac] + 1
		else:
			if mac in mac_list:
				print (mac, mac_time, str(res[3]), str(info))
				if mac in list(mac_list_dict.keys()):
					mac_list_dict[mac].append(info)
				else:
					mac_list_dict[mac] = []
					mac_list_dict[mac].append(info)
	conn.commit()
	print (cnt)
	return mac_list_dict

'''
search top_n mac
'''

def search_top_n(cur, conn, sql):
	mac_list = []
	cur.execute(sql)
	res = cur.fetchall()
	for i in res:
		mac_list.append(i)
	del res
	return mac_list

def main():
	f = open('2019_7_22_19_41_json.txt', 'w', encoding="UTF-8")
	choice = 0
	conn = pymysql.connect(host='223.3.76.188', user='gu', passwd='ibmc51', db='80211_AC',charset='utf8', port=3306)
	cur = conn.cursor()
	mac_list = ["9c:e3:3f:dc:fa:cc"]
	# mac address top cnt
	cnt = 500
	top_mac_list = []
	# reset cursor
	# search info of mac list
	search_sql = "select * from probe_req"
	if (choice == 0):
		res = search_info(cur, conn, mac_list, search_sql, "2018-07-23 11:00:00", 1)
	elif (choice == 1):
		top_sql = "select src_mac, count(*) AS count from probe_req group by src_mac order by count desc limit %s" %(cnt)
		mac_list_raw = search_top_n(cur, conn, top_sql)
		mac_list = []
		for i in mac_list_raw:
			if not IsLocalMac(i[0]):
				mac_list.append(i[0])
		cur.scroll(0, mode='absolute')
		res = search_info(cur, conn, mac_list, search_sql, "2018:01:01 01:00:00", 0)
		print (sys.getsizeof(str(res)))
		# print (mac_list)
		filtered_mac = list()
		# print (filtered_mac)
	# f_str.write(str(res))
	w_res = json.dumps(res, indent=4)
	del res
	f.write(w_res)
	f.close()
	cur.close()
	conn.close()

if __name__=='__main__':
	main()
