# -*- coding: utf-8 -*-
'''
deal with a method using reading text
'''

from math import log, isclose
import json
import sys, getopt

field_set = {"rx_highest": [], "tx_highest": [], 'ext_capab': [], 'supp_rates': [], 'a_mpdu_param': [],
             'ht_capabilities_info': [], 'ht_extend_capabilities': [], 'asel_capabilities': [], 'rx_map': [],
             'tx_bf_capability_info': [], 'tx_highest': [], 'tx_map': [], 'vendor_list': [], 'supported_mcs_set': [],
             'vht_capabilities_info': [], 'ext_supp_rates': []}
field_keys = ["rx_highest", "tx_highest", 'ext_capab', 'supp_rates', 'a_mpdu_param', 'ht_capabilities_info',
              'ht_extend_capabilities', 'asel_capabilities', 'rx_map', 'tx_bf_capability_info', 'tx_map',
              'vendor_list', 'supported_mcs_set', 'vht_capabilities_info', 'ext_supp_rates']
field_len = dict(zip(field_keys, [0] * len(field_keys)))

def find_bit_field(final_index, field_keys):
    bit_to_field = []
    curr_n = 0
    for i in field_keys:
        tmp = [(curr_n, curr_n + field_len[i] - 1), i]
        curr_n = curr_n + field_len[i]
        bit_to_field.append(tmp)
    for i in final_index:
        for j in bit_to_field:
            if j[0][0] <= i <= j[0][1]:
                print (i, ":", i - j[0][0] + 1, ":", j[1])
                break

def str_choose(f_str, index):
    res_str = ''
    for i in index:
        res_str = res_str + f_str[i]
    return res_str

def feature_bin(field_key, field_info, field_len):
    res_str = ""
    res_bin_str = ""
    if field_key in field_info.keys():
        if field_key in ["ext_supp_rates", "supp_rates", "supported_mcs_set", "ext_capab", "vendor_list"]:
            for i in field_info[field_key]:
                res_str = res_str + i
        else:
            res_str = res_str + field_info[field_key]
        for i in res_str:
            if i == ':':
                continue
            tmp = bin(int(i, 16))
            tmp = tmp[2:]
            tmp = tmp.zfill(4)
            res_bin_str = res_bin_str + tmp


    # print (type(res_bin_str), f_len)
    res_bin_str = res_bin_str.ljust(field_len[field_key], '2')
    # print("field_key: %s, res_bin_str: %s" % (field_key, res_bin_str))
    return res_bin_str


# only one field but include all samples
# '''
# field_set: ['11111','11111']
# '''
def row_to_col(var_bin_set):
    every_field_set = []
    str_len = len(var_bin_set[0])
    for index in range(str_len):
        tmp_str = ""
        for i in var_bin_set:
            # print("i: %s, index: %d" % (i, index))
            tmp_str = tmp_str + i[index]
        every_field_set.append(tmp_str)
    return every_field_set

def cal_fields_variable_entropy(var_field_set):
    entropy_set = []
    # fill the value
    for i in var_field_set:
        cnt_0 = 0
        cnt_1 = 0
        cnt_2 = 0
        cnt = 0
        for j in i:
            if j == '0':
                cnt_0 = cnt_0 + 1
            elif j == '1':
                cnt_1 = cnt_1 + 1
            else:
                cnt_2 = cnt_2 + 1
            cnt = cnt + 1
        p_0 = float(cnt_0) / cnt
        p_1 = float(cnt_1) / cnt
        p_2 = float(cnt_2) / cnt
        if cnt_0 == 0:
            e_0 = 0.0
        else:
            e_0 = p_0 * log(p_0, 3)
        if cnt_1 == 0:
            e_1 = 0.0
        else:
            e_1 = p_1 * log(p_1, 3)
        if cnt_2 == 0:
            e_2 = 0.0
        else:
            e_2 = p_2 * log(p_2, 3)

        entropy = (e_0 + e_1 + e_2) * (-1)
        # print ("e_0: %f, e_1: %f, e_2:%f" % (e_0, e_1, e_2))
        entropy_set.append(entropy)
    return entropy_set


# '''
# one device
# field_set: ["1111", "1111"]
# return: [0.1, 0.2]
# '''

def cal_fields_stable_entropy(stable_field_set):
    stable_entropy_set = []
    for i in stable_field_set:
        cnt_0 = 0
        cnt_1 = 0
        cnt_2 = 0
        cnt = 0
        for j in i:
            if j == '0':
                cnt_0 = cnt_0 + 1
            elif j == '1':
                cnt_1 = cnt_1 + 1
            else:
                cnt_2 = cnt_2 + 1
            cnt = cnt + 1
        p_0 = float(cnt_0) / cnt
        p_1 = float(cnt_1) / cnt
        p_2 = float(cnt_2) / cnt
        if cnt_0 == 0:
            e_0 = 0.0
        else:
            e_0 = p_0 * log(p_0, 3)
        if cnt_1 == 0:
            e_1 = 0.0
        else:
            e_1 = p_1 * log(p_1, 3)
        if cnt_2 == 0:
            e_2 = 0.0
        else:
            e_2 = p_2 * log(p_2, 3)
        stable_entropy = 1 - (e_0 + e_1 + e_2) * (-1)
        stable_entropy_set.append(stable_entropy)
    return stable_entropy_set


## thershold , print the location of bit

def top_great_choice(res, th):
    index_l = []
    for i in res:
        if i['value'] > th:
            index_l.append(i['index'])
    return index_l

def top_n_choice(dual_res, th):
    index_l = []
    for i in dual_res:
        if isclose(i['value'], th):
            index_l.append(i['index'])
    return index_l

def main(argv):
    mac_duplicate = []
    var_bin_set = []
    stable_bin_set = []
    key_bin_set = {} # all data corresponding to mac

    sum_len = 0
    stable_th = 1
    var_th = 0.5
    try:
        opts, args = getopt.getopt(argv, "i:", ["input="])
    except getopt.GetoptError:
        print('-i [filename]')
        sys.exit(2)
    for opt, arg in opts:
        if opt in ("-i", "--input"):
            inputfile = arg
    f = open(inputfile, 'r')
    f_con = f.read()
    # f_con.replace('/', '')
    f_json = json.loads(f_con)

    # form field_len
    for i in f_json.keys():
        for j in f_json[i]:
            l = json.loads(j)
            for t in field_keys:
                if t in l.keys():
                    field_len[t] = max(field_len[t], len(l[t]))
                else:
                    pass

    # modify the length of field_len
    for t in field_len.keys():
        if t in ["ext_supp_rates", "supp_rates", "supported_mcs_set", "ext_capab"]:
            field_len[t] = field_len[t] * 2 * 4
        elif t == 'vendor_list':
            field_len[t] = field_len[t] * 6 * 4
        else:
            field_len[t] = field_len[t] * 4
    print (field_len)
    for i in field_len.keys():
        sum_len = sum_len + field_len[i]
    print ("length of sum: %d" % (sum_len))
    # form variable, different
    for i in f_json.keys():
        j = f_json[i][0]
        l = json.loads(j)
        bin_str = ""
        for t in field_keys:
            bin_str = bin_str + feature_bin(t, l, field_len)
        var_bin_set.append(bin_str)

    var_entropy = cal_fields_variable_entropy(row_to_col(var_bin_set))

    # calculate stable, not considering the high entropy correspond to which bit or which field
    tmp_res = []
    for i in f_json.keys():
        tmp_set = []
        for j in f_json[i]:
            second_bin_str = ""
            l = json.loads(j)
            for t in field_keys:
                second_bin_str = second_bin_str + feature_bin(t, l, field_len)
            tmp_set.append(second_bin_str)
        tmp_res.append(cal_fields_stable_entropy(row_to_col(tmp_set)))
        key_bin_set[i] = tmp_set

    # print (tmp_res)
    stable_entropy = []
    bit_field_len = len(tmp_res[0])
    for i in range(bit_field_len):
        tmp = 0
        for j in tmp_res:
            tmp = tmp + j[i]
        stable_entropy.append(tmp / len(f_json.keys()))
    # result variable
    dual_res = []
    stable_entropy_res = []
    var_entropy_res = []

    for i in range(len(stable_entropy)):
        dual_res.append({"index": i, "value": stable_entropy[i] * var_entropy[i]})
    for i in range(len(stable_entropy)):
        stable_entropy_res.append({"index": i, "value": stable_entropy[i]})
    index_stable = top_n_choice(stable_entropy_res, stable_th)
    for i in index_stable:
        var_entropy_res.append({"index": i, "value": var_entropy[i]})
    final_index = top_great_choice(var_entropy_res, var_th)
    print (final_index)
    '''
    find the feature bit corresponding to the 
    '''
    find_bit_field(final_index, field_keys)
    '''
    complete matching
    
    '''
    index_key = list(key_bin_set.keys())

    '''
    reduce the duplicate mac
    '''
    hash_unique = {}
    key_noduplicate_bin_set = {}
    for i in index_key:
        key_noduplicate_bin_set[i] = []
        hash_unique[i] = []
        for j in key_bin_set[i]:
            if len(hash_unique) == 0 or hash(j) not in hash_unique[i]:
                hash_unique[i].append(hash(j))
                key_noduplicate_bin_set[i].append(j)

    # accurate_mac_duplicate = []
    # hash_mac_tuple = []
    # for i in range(0, len(index_key) - 1):
    #     for j in range(1, len(index_key) - i):
    #         for t in range(len(key_bin_set[index_key[i]])):
    #             for z in range(len(key_bin_set[index_key[i + j]])):
    #                 if key_bin_set[index_key[i]][t] == key_bin_set[index_key[i + j]][z]:
    #                     # print (hash(key_bin_set[index_key[i]][t]), hash(key_bin_set[index_key[i + j]][z]))
    #                     a_l = [index_key[i], index_key[i + j]]
    #                     if (len(hash_mac_tuple) == 0):
    #                         hash_mac_tuple.append(hash(str(a_l)))
    #                         print (a_l)
    #                     elif hash(str(a_l))not in hash_mac_tuple:
    #                         hash_mac_tuple.append(hash(str(a_l)))
    #                         print (a_l)
    #                     break

    '''
    accurate matching according the final index
    form key: [bin]
    '''
    hash_bin_unique = []
    for i in range(0, len(index_key) - 1):
        for j in range(1, len(index_key) - i):
            for t in range(len(key_noduplicate_bin_set[index_key[i]])):
                for z in range(len(key_noduplicate_bin_set[index_key[i + j]])):
                    if str_choose(key_noduplicate_bin_set[index_key[i]][t], final_index) == str_choose(key_noduplicate_bin_set[index_key[i + j]][z], final_index):
                        # print ("equal fingerprint information: key_1: %s, key_2: %s, key_1 fn: %d, key_2 fn: %d" % (index_key[i], index_key[i + j], t, z))
                        s_l = [index_key[i], index_key[i + j]]
                        if (len(hash_bin_unique) == 0):
                            hash_bin_unique.append(hash(str(s_l)))
                            print (s_l)
                        elif hash(str(s_l)) not in hash_bin_unique:
                            hash_bin_unique.append(hash(str(s_l)))
                            print (s_l)
                        break
    print ("mac duplicate:", mac_duplicate)


    f.close()


if __name__ == '__main__':
    main(sys.argv[1:])