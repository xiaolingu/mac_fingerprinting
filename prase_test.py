from scapy.all import *
feature_dict = {"scan_avg":0, "interval_avg":0, "cnt_avg": 0, "channel": 5180}
'''
1. data struct:
    @mac
    @channel
    @data = [{seq: , channel: , time: }]

2. network interface card: 
2.1. setting of channel selections
36-40 40-44 44-48 48-52
[5180 - 5200] [5200 - 5220] [5220 - 5240] [5240 - 5260]
12 bits sequence number mod 4096
'''
one_seq_t = 2
channel_num = 4
channels = [5180, 5200, 5220, 5240]
seq_mod = 4096

class mac_data:
    def __init__(self, mac, channel):
        self.mac = mac
        self.channel = channel
        self.data = list()

def str_to_channel(filename):
    # remove suffix
    filename_prefix = filename.split('.')[-2]
    return int(filename_prefix.split('_')[-1])

def seq_converter(args):
    tmp = "%04x" % args
    bin_res = '0x' + tmp[0:3]
    oct_res = int(bin_res, 16)
    return oct_res

def dwell_one_seq_cal(raw_data, uptime):
    time_seq = []
    for i in range(1, len(raw_data)):
        tmp = raw_data[i]['time'] - raw_data[i - 1]['time']
        if tmp < uptime:
            time_seq.append(tmp)
    return sum(time_seq) / len(time_seq)

def dwell_num(raw_data, uptime):
    cnt = len(raw_data) - 1
    interval_cnt = 0
    for i in range(1, len(raw_data)):
        tmp = raw_data[i]['time'] - raw_data[i - 1]['time']
        if tmp > uptime:
            interval_cnt = interval_cnt + 1
    circle = interval_cnt + 1
    return float(cnt) / circle

def single_circle_time_cal(raw_data, uptime):
    # calculate channel scanning time and seq
    scanning_time = []
    curr_ts = 0
    prev_ts = 0
    cnt = 0
    for j in raw_data:
        if cnt == 0:
            prev_ts = j['time']
            curr_ts = prev_ts
            prev_seq = j['seq']
            curr_seq = prev_seq
        else:
            curr_ts = j['time']
            curr_seq = j['seq']
            if (curr_ts - prev_ts) > uptime:
                scanning_time.append(curr_ts - prev_ts)
        cnt = cnt + 1
        prev_ts = curr_ts    
        prev_seq = curr_seq 
    print (scanning_time)  
    return scanning_time

def single_circle_seq_cal(raw_data, uptime):
    scanning_time = []
    scanning_seq = []
    cnt = 0
    curr_seq = 0
    prev_seq = 0
    curr_ts = 0
    prev_ts = 0
    for j in raw_data:
        if cnt == 0:
            prev_ts = j['time']
            curr_ts = prev_ts
            prev_seq = j['seq']
            curr_seq = prev_seq
        else:
            curr_ts = j['time']
            curr_seq = j['seq']
            if (curr_ts - prev_ts) > uptime:
                scanning_time.append(curr_ts - prev_ts)
                scanning_seq.append((curr_seq - prev_seq + 4096) % 4096)
        cnt = cnt + 1
        prev_ts = curr_ts    
        prev_seq = curr_seq   
    print (scanning_seq)
    return scanning_seq

## deprecated function
def all_freq(filename_set, mac):
    all_freq_packet = []
    for i in filename_set:
        all_freq_packet.extend(handle_rtl_packet(i, mac, str_to_channel(i)).data)
    all_freq_packet.sort(key=lambda x:x['time'])
    return all_freq_packet

def channel_hopping_feature(start_ch, end_ch, start_raw_packet, end_raw_packet):
    '''
    calculate the list of difference of time and seq in channel hopping
    return time and sequence difference
    '''
    chs_packet = []
    chs_packet.extend(start_raw_packet)
    chs_packet.extend(end_raw_packet)
    # sort by time
    chs_packet.sort(key=lambda x:x['time'])
    delta_t_l = []
    delta_seq_l = []

    for i in range(0, len(chs_packet) - 1):
        print (chs_packet[i])
        if chs_packet[i]['channel'] == start_ch and chs_packet[i + 1]['channel'] == end_ch:
            delta_t = chs_packet[i + 1]['time'] - chs_packet[i]['time']
            delta_seq = chs_packet[i + 1]['seq'] - chs_packet[i]['seq']
            delta_seq_l.append(delta_seq)
            delta_t_l.append(delta_t)
    print (delta_t_l, delta_seq_l)
    return delta_t_l, delta_seq_l

    
def handle_ath_packet(filename, mac):
    frame_ts_time = []
    curr_ts_s = []
    prev_ts_s = []
    prev_ts = 0
    curr_ts_wireshark = 0
    curr_ts_ms = 0
    scan_sum = 0
    interval_sum = 0
    cnt = 0
    arr_cnt = 0
    curr_seq = 0
    prev_seq = 0
    diff = []
    with PcapReader(filename) as pcap_reader:
        try:
            for pkt in pcap_reader:
                if pkt.haslayer(Dot11):            
                    if pkt.subtype == 4 and pkt.type == 0 and pkt.addr2 == mac:
                        curr_ts_wireshark = pkt.time
                        curr_ts_ms = pkt.mac_timestamp
                        curr_seq = seq_converter(pkt.SC)
                        frame_ts_time.append((curr_ts_wireshark, curr_ts_ms, curr_seq))
                        cnt = cnt + 1
                        print ('%f, %d, %d' % (curr_ts_wireshark, curr_ts_ms, seq_converter(pkt.SC)))
        except EOFError:
            pass
        frame_ts_time.sort(key=lambda x:x[0])
        for i in range(len(frame_ts_time)):
            print (frame_ts_time[i][0], frame_ts_time[i][1], frame_ts_time[i][2])
            if i == 0:
                pass
            else:
                diff.append((frame_ts_time[i][0] - frame_ts_time[i - 1][0], frame_ts_time[i][1] - frame_ts_time[i - 1][1], frame_ts_time[i][2] - frame_ts_time[i - 1][2]))
        print (diff)

def handle_rtl_packet(filename, mac, channel):
    packet = mac_data(mac, channel)
    frame_ts_time = []
    with PcapReader(filename) as pcap_reader:
        try:
            for pkt in pcap_reader:       
                if pkt.subtype == 4 and pkt.type == 0 and pkt.addr2 == mac and pkt.info == b'':
                    curr_ts_wireshark = pkt.time
                    curr_seq = seq_converter(pkt.SC)
                    curr_channel = pkt.Channel
                    packet.data.append({'time': curr_ts_wireshark, 'seq': curr_seq, 'channel': pkt.Channel})
                    print ('%f, %d, %d' % (curr_ts_wireshark, seq_converter(pkt.SC), curr_channel))
        except EOFError: 
            pass
    return packet         
if __name__ == "__main__":
    filename_set = ['./pcap_dataset/liu_gu_36.pcap', './pcap_dataset/liu_gu_40.pcap']
    filename = './pcap_dataset/cmp/ac1750_mac_e32_channel_36.pcap'
    mac = ["bc:fe:d9:df:ed:7f", "9c:e3:3f:dc:fa:cc"]
    # handle_packet(filename, mac)
    '''
    each channel feature selection
    '''
    # for i in mac:
    #     packet = handle_rtl_packet(filename, i, str_to_channel(filename))
    #     print (dwell_one_seq_cal(packet, one_seq_t))
    #     print (dwell_num(packet, one_seq_t))

    '''
    all channel seq
    '''
    if __debug__:

        # all_channel_data = all_freq(filename_set, mac[1])
        # for i in all_channel_data:
        #     print (i)
        # for i in mac:
        #     start_p = handle_rtl_packet(filename_set[0], i, str_to_channel(filename_set[0]))
        #     end_p = handle_rtl_packet(filename_set[1], i, str_to_channel(filename_set[1]))
        #     channel_hopping_feature(5180, 5200, start_p.data, end_p.data)

        for i in mac:

            l = handle_rtl_packet(filename_set[0], i, str_to_channel(filename_set[0]))
            single_circle_seq_cal(l.data, one_seq_t)
            print (dwell_num(l.data, one_seq_t))
            single_circle_time_cal(l.data, one_seq_t)
            print (dwell_one_seq_cal(l.data, one_seq_t))
            

