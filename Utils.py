import re

# for all IP address
import time
import datetime

# ip_reg = re.compile('(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)')

# MUNI net 147.251.0.0/16
ip_reg = re.compile('147\.251\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)')
src_port_reg = re.compile('147\.251\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?);(\d+)')
time_reg = re.compile('(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})')
major_minor_reg = re.compile('\d*\.\d*')

# Windows
win_version = re.compile('(?<=windows)\d+\.\d+')
win_reg1 = re.compile('update\.microsoft\.com')
# DNS query
win_reg2 = re.compile('download.windowsupdate.com')
# maybe
win_reg3 = re.compile('weather\.microsoft\.com')
# IE connection
win_reg4 = re.compile('client\.wns\.windows\.com')
win_reg5 = re.compile('msftconnecttest\.com')
win_reg6 = re.compile('watson\.telemetry\.microsoft\.com')
win_reg7 = re.compile('statsfe2\.update\.microsoft\.com')
win_reg8 = re.compile('dmd\.metaservices\.microsoft\.com')
win_reg9 = re.compile('msftncsi\.com')
win_reg10 = re.compile('ctldl\.windowsupdate\.com')
win_reg11 = re.compile('microsoft\.com\.nsatc\.net')
win_reg12 = re.compile('login\.live\.com')
win_reg13 = re.compile('dl\.delivery\.mp\.microsoft\.com')
win_reg14 = re.compile('au\.windowsupdate\.com')
win_reg15 = re.compile('vortex-win\.data\.microsoft\.com')
win_reg16 = re.compile('g\.ceipmsn\.com')
win_reg17 = re.compile('cdn\.content\.prod\.cms\.msn\.com')
win_reg18 = re.compile('-pro.d.dsp.mp.microsoft.com')
win_reg19 = re.compile('au.download.windowsupdate.com')
win_reg20 = re.compile('settings-win.data.microsoft.com')
win_reg21 = re.compile('e-service.weather.microsoft.com')
win_reg22 = re.compile('settings-win.data.microsoft.com')
win_reg23 = re.compile('g.ceipmsn.com')
win_reg24 = re.compile('msn-com.akamaized.net')
win_reg25 = re.compile('am.microsoft.com')
win_reg26 = re.compile('arc.msn.com')
win_reg27 = re.compile('sls.update.microsoft.com')
win_reg28 = re.compile('oem.twimg.com')
win_reg29 = re.compile('urs.smartscreen.microsoft.com')
win_reg30 = re.compile('dsp.mp.microsoft.com')
win_reg31 = re.compile('activity.windows.com')
win_reg32 = re.compile('ocsp.msocs\.com')
win_reg33 = re.compile('vl\.ff\.avast\.com')



# MAC OS and OS X
mac_reg1 = re.compile('swscan\.apple\.com')
mac_reg2 = re.compile('swcdn\.apple\.com')
# OS X 10.8+ few collisions with windows (iTunes)
mac_reg3 = re.compile('swdist\.apple\.com')
# icloud servers
mac_reg4 = re.compile('\.icloud\.com')
mac_reg5 = re.compile('cl[1-5]\.apple.com')
mac_reg6 = re.compile('gs-loc.apple.com')
mac_reg7 = re.compile('itunes.apple.com')
mac_reg8 = re.compile('.push.apple.com')
mac_reg9 = re.compile('xp.apple.com')
mac_reg10 = re.compile('captive.apple.com')
mac_reg11 = re.compile('configuration.apple.com')
mac_reg12 = re.compile('ssl.ls.apple.com')
mac_reg13 = re.compile('mesu.apple.com')
mac_reg14 = re.compile('guzzoni.apple.com')
mac_reg15 = re.compile('.ls.apple.com')
mac_reg16 = re.compile('pancake.apple.com')



# Linux
# canonical net 91.189.88.0/21
canonical_net = re.compile('91\.189\.(?:88|89]|9[0-5]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)')
# updates sites from canonical
linux_reg1 = re.compile('canonical\.com')
# updates sites from ubunu
linux_reg2 = re.compile('security\.ubuntu\.com')
linux_reg3 = re.compile('archive\.ubuntu\.com')
# Ubuntu error tracker submission, it makes a DNS query for daisy.ubuntu.com on every boot
linux_reg4 = re.compile('daisy\.ubuntu\.com')
# Ubuntu NTP server, it makes a DNS query for ntp.ubuntu.com on every boot
linux_reg5 = re.compile('ntp\.ubuntu\.com')
# maybe
linux_reg6 = re.compile('ubuntu\.pool\.ntp\.org')


# Android
# connectivitycheck for android 5 or older
android_reg1 = re.compile('connectivitycheck\.android\.com')
# connectivitycheck for android 6 or newer
android_reg2 = re.compile('connectivitycheck\.gstatic\.com')
# DNS query for default NTP android 5 or older
android_reg3 = re.compile('android\.pool\.ntp\.org')
# DNS query for default NTP android 6 or newer
android_reg4 = re.compile('api.sec.miui.com')
android_reg5 = re.compile('android\.clients\.google\.com')
android_reg6 = re.compile('clients3\.google\.com;;/generate_204')
android_reg7 = re.compile('cloudconfig\.googleapis\.com')
android_reg8 = re.compile('helpnewsrepublic1.ksmobile.com')
android_reg9 = re.compile('portal.fb.com')
android_reg10 = re.compile('mqtt-mini.facebook.com')
android_reg11 = re.compile('[^8]api.accuweather.com')
android_reg12 = re.compile('data.mistat.xiaomi.com')
android_reg13 = re.compile('ms.cmcm.com')
android_reg14 = re.compile('cmdts.ksmobile.com')
android_reg15 = re.compile('micloud.xiaomi.net')


# Fedora
fed_reg1 = re.compile('fedoraproject\.org;;/static/hotspot\.txt')

# Blackberry
bb_reg1 = re.compile('icc\.blackberry\.com')
bb_reg2 = re.compile('inet\.icrs\.blackberry\.com')


eduroam_path = 'FINAL/dict/eduroam_log.csv'
eduroam_path_with_users = 'FINAL/dict/eduroam_log_may_with_users.csv'
flow_path = 'flow.csv'
session_path = 'FINAL/sessions.csv'
session_final_path = 'FINAL/sessions_out_out_out.csv'
final_session_path = 'FINAL/sessions_out_out_out.csv'
finger_path = 'FINAL/dict/fingersDB_sorted_full_map.csv'
dhcp_path = 'FINAL/dict/DHCP_dict.csv'
time_path = 'FINAL/aktualne/time_plus_5_minutes.csv'

'''--------------------------------------------------METHODS--------------------------------------------------'''


# remove unused sessions with zero bytes
def clean_eduroam_log(path):
    with open(path, 'r') as eduroam:
        new_path = path[:-4] + '_out.csv'
        with open(new_path, 'w') as new_eduroam:
            for line in eduroam:
                if line[-5:-1] != ';0;0':
                    new_eduroam.write(line)


# remove flows which contains ; in URL
def clean_flows(path):
    remove_space_reg = re.compile('[\w]+.*[\w]+|\w')
    with open(path, 'r') as flow:
        new_path = path[:-4] + '_out.csv'
        with open(new_path, 'w') as new_flow:
            flow.readline()
            new_flow.write('Date first seen;Date last seen;Proto;Src IP;Addr Src Pt;Dst IP Addr;Dst Pt;Packets;Bytes;Flows;HTTP Host OS;HTTP Host OS Major Version;HTTP Host OS Minor Version;HTTP Host OS Build Version;TCP window size;TCP syn size;TCP TTL;HTTP hostname;DNS Question Name;HTTP URL;\n')
            for line in flow:
                if line.count(';') == 20:
                    new_flow.write(line.replace(' ', '') + '\n')


def remove_without_session_id():
    with open(flow_path, 'r') as flows_in:
        with open(flow_path[:-4] + '_out.csv', 'w') as flows_out:
            flows_out.write(flows_in.readline())
            for line in flows_in:
                if line.split(';')[21] != '':
                    flows_out.write(line)


def get_vendor(str):
    if 'Android' in str:
        return 'Google'
    if 'Windows' in str:
        return 'Microsoft'
    if 'Mac' in str or 'iOS' in str or 'Darwin' in str:
        return 'Apple'
    if 'Ubuntu' in str or 'Linux' in str or 'Fedora' in str:
        return 'Linux/Unix'
    if 'BlackBerry' in str:
        return 'BlackBerry'
    return ''


def get_vendor_OS_name(str):
    if 'Windows' in str:
        return 'Microsoft;Windows'
    if 'Windows Phone' in str:
        return 'Microsoft;Windows Phone'

    if 'Mac' in str:
        return 'Apple;Mac OS X'
    if 'iOS' in str:
        return 'Apple;iOS'
    if 'Darwin' in str:
        return 'Apple;Darwin'

    if 'Android' in str:
        return 'Google;Android'
    if 'Chrome OS' in str:
        return 'Google;Chrome OS'

    if 'Debian' in str:
        return 'Linux/Unix;Debian'
    if 'Ubuntu' in str:
        return 'Linux/Unix;Ubuntu'
    if 'Fedora' in str:
        return 'Linux/Unix;Fedora'
    if 'Linux' in str:
        return 'Linux/Unix;'

    if 'BlackBerry' in str:
        return 'Other;BlackBerry'

    if str != '':
        return 'Other;'
    return ';'


def get_major_minor(str):
    if not major_minor_reg.search(str):
        return ';'
    tmp = major_minor_reg.search(str).group(0).split('.')
    return tmp[0] + ';' + tmp[1]


def split_OS(OS, size):
    result = get_vendor_OS_name(OS) + ';'
    if size == 4:
        if 'Other' not in result:
            result += get_major_minor(OS) + ';'
        else:
            result += ';;'
    return result


def create_time_skeleton():
    with open('FINAL/aktualne/time_plus_3_minutes.csv', 'w') as time:
        base = datetime.datetime.strptime('2017-05-01 00:00:00', "%Y-%m-%d %H:%M:%S")
        baseP = datetime.datetime.strptime('2017-05-01 00:03:00', "%Y-%m-%d %H:%M:%S")
        for _ in range(604800):
            time.write(base.strftime("%Y-%m-%d %H:%M:%S") + ';' + baseP.strftime("%Y-%m-%d %H:%M:%S") + ';\n')
            base += datetime.timedelta(seconds=1)
            baseP += datetime.timedelta(seconds=1)



def create_skeleton_for_flow_triple_detection():
    with open(session_path, 'r') as session_in:
        with open(session_path[:-4] + '_out.csv', 'w') as session_out:
            session_out.write('ID;start;end;IP;OS;\n')
            session_in.readline()
            for line in session_in:
                array = line.split(';')
                if array[7] == '':
                    continue
                time = (datetime.datetime.strptime(array[1], "%Y-%m-%d %H:%M:%S") + datetime.timedelta(minutes=10)).strftime("%Y-%m-%d %H:%M:%S")
                if time < array[2]:
                    array[2] = time
                for tmp in array[:4]:
                    session_out.write(tmp + ';')
                session_out.write(get_vendor_OS_name(array[7]) + ';\n')

# create_skeleton_for_flow_triple_detection()


def idk():
    with open('FINAL/aktualne/flow_first_10_min.csv', 'r') as input:
        input.readline()
        result = {}
        for line in input:
            array = line.split(';')
            id = array[21]
            if id not in sessions_dict_id:
                continue
            session = sessions_dict_id[id]
            finger = repr(array[10:19])

            if finger not in result:
                result[finger] = {}
            if session[4] not in result[finger]:
                result[finger][session[4]] = {}
            if session[5] not in result[finger][session[4]]:
                result[finger][session[4]][session[5]] = 1
            else:
                result[finger][session[4]][session[5]] += 1
        return result


def save_idk():
    with open('FINAL/aktualne/idk.csv', 'w') as output:
        output.write('Stamp;Vendor;OS_name;size;\n')
        result = idk()
        for vendor in result:
            for OS in result[vendor]:
                for stamp in result[vendor][OS]:
                    output.write(vendor + ';' + OS + ';' + stamp + ';' + repr(result[vendor][OS][stamp]) + ';\n')


def load_idk_fingers():
    with open('FINAL/aktualne/idk.csv', 'r') as input:
        with open('FINAL/aktualne/idk_out.csv', 'w') as output:
            output.write('Stamp;Vendor;OS_name;\n')
            input.readline()
            result = {}
            for line in input:
                array = line.split(';')
                if array[0] not in result:
                    result[array[0]] = {}
                if array[1] not in result[array[0]]:
                    result[array[0]][array[1]] = {}
                if array[2] not in result[array[0]][array[1]]:
                    result[array[0]][array[1]][array[2]] = array[3]
                else:
                    print('problem')
            result = recalc_idk_fingers(result)
            for stamp in result:
                output.write(stamp + result[stamp])

def recalc_idk_fingers(result):
    final = {}

    for stamp in result:
        v = None
        o = None
        max = 99
        counter = 0
        for vendor in result[stamp]:
            for OS in result[stamp][vendor]:
                counter += int(result[stamp][vendor][OS])
                if int(result[stamp][vendor][OS]) > max:
                    max = int(result[stamp][vendor][OS])
                    v = vendor
                    o = OS
        if v != None and o != None:
            final[stamp] = ';' + v + ';' + o + ';' + repr(max) + ';' + repr(float(max)/counter) + ';\n'
    return final

# 10 hos
# 11 major
# 12 minor
# 13 build
# 14 tcp size
# 15 syn size
# 16 TTL
# 17 url
# 18 dns

# merge same OS with/out version
def merge_same_sub_os(source):
    results = []
    for record in source:
        contains = False
        for result in results:
            if record in result:
                contains = True
            if result in record:
                results.remove(result)
        if not contains:
            results.append(record)

    return results


# get first and last seen from string as array
def get_time(str):
    return time_reg.findall(str)


# get src ip from string
def get_ip(str):
    return ip_reg.search(str).group(0)


def get_all_ip(str):
    return ip_reg.findall(str)


# check if traffic was during session
def is_between(traffic_time, session_time):
    return traffic_time[0] >= session_time[0] and traffic_time[1] <= session_time[1]


# get session ID
def get_id(session_line):
    return session_line[:session_line.index(';')]


# get src port
def get_src_port(record):
    return src_port_reg.search(record).group(1)


# for quick search in files
def quick_select(path, string):
    with open(path, 'r') as flow:
        counter = 0
        ip = []
        for line in flow:
            if '' in line and string in line:
                print(line[:-1])
                counter += 1
        print(counter)


# for quick search in files
def check_domain():
    id = {}
    with open('data/flows/10-0-111-130-may/10-0-111-130--05-01_out_out.csv', 'r') as flow:
        for line in flow:
            if 'swdist.apple.com' in line:
                if line[:-1].split(';')[20] not in id:
                    id[line[:-1].split(';')[20]] = None
    with open('data/sessions_out_out.csv', 'r') as session:
        for line in session:
            if get_id(line) in id:
                print(line.split(';'))


# check_domain()
'''-------------------------------------------------------DICTIONARY------------------------------------------------'''


def create_session_id_to_mac_dict():
    with open(final_session_path, 'r') as session:
        result = {}
        session.readline()
        for line in session:
            array = line.split(';')
            if array[0] in result:
                print("ERROR")
            result[array[0]] = array[17]
        return result


# create dictionary from eduroam log by IP address
# usage: dict[IP] return list of sessions with same IP address
def create_eduroam_dict():
    with open(eduroam_path, 'r') as eduroam:
        eduroam.readline()
        result = {}
        for record in eduroam:
            if get_ip(record) not in result:
                result[get_ip(record)] = [[get_id(record), get_time(record)]]
            else:
                result[get_ip(record)].append([get_id(record), get_time(record)])
    return result

# create dictionary from session file by IP address
# usage : dict[ip_address] return list of sessions with same IP
def create_session_dict_by_id_OS():
    # path to eduroam session file
    with open(session_final_path, 'r') as sessions:
        # ignore first line
        sessions.readline()
        dict = {}
        for session in sessions:
            record = session.split(';')[:-1]
            dict[record[0]] = record[16]
        return dict


# create dictionary from session file by IP address
# usage : dict[ip_address] return list of sessions with same IP
def create_session_dict_by_ip():
    # path to eduroam session file
    with open(session_final_path, 'r') as sessions:
        # ignore first line
        sessions.readline()
        dict = {}
        for session in sessions:
            record = session.split(';')[:-1]
            if record[3] not in dict:
                dict[record[3]] = [record]
            else:
                dict[record[3]].append(record)
        return dict


# create dictionary from session file by IP address
# usage : dict[id] return current session with same ID
def create_session_dict_by_id():
    # path to eduroam session file
    with open(session_path, 'r') as sessions:
        # ignore first line
        sessions.readline()
        dict = {}
        for session in sessions:
            dict[get_id(session)] = session.split(';')[:-1]
        return dict


# create dictionary from TCP stack
# usage : dict[SYN][WIN][TTL] return array with OS and their %
def create_fingers_dict():
    # path to eduroam session file
    with open(finger_path, 'r') as fingers:
        # ignore first line
        fingers.readline()
        result = {}
        for record in fingers:
            array = record.split(';')
            syn = int(array[1])
            win = int(array[2])
            ttl = int(array[3])
            try:
                # groups with more than 1 OS [SYN][WIN][TTL]
                result[syn][win][ttl].append([array[0], array[4:7], array[8]])
            except KeyError:
                if syn not in result:
                    result[syn] = {}
                if win not in result[syn]:
                    result[syn][win] = {}
                if ttl not in result[syn][win]:
                    result[syn][win][ttl] = [[array[0], array[4:7], array[8]]]
        return result


# usage : dict[id] return array with OS and their %
def create_fingers_dict_id():
    # path to eduroam session file
    with open(finger_path, 'r') as fingers:
        # ignore first line
        fingers.readline()
        result = {}
        for record in fingers:
            array = record.split(';')
            id = int(array[0])
            OS = array[4]
            major = array[5]
            minor = array[6]
            perc = array[8]
            if major != 'N/A':
                OS += ' ' + major
                if minor != 'N/A':
                    OS += '.' + minor
            if id in result:
                result[id].append([OS, perc])
            else:
                result[id] = [[OS, perc]]
        return result


def create_eduroam_with_names_dict():
    with open(eduroam_path_with_users, 'r') as eduroam:
        eduroam.readline()
        result = {}
        for line in eduroam:
            if ';0;0' not in line:
                array = line.split(';')
                if len(array) == 10:
                    result[array[0]] = array[9][:-1]
        return result


def return_MVP_element(dic):
    max = 0
    element = ''
    for tmp in dic:
        if dic[tmp] > max:
            max = dic[tmp]
            element = tmp
    return element

'''------------------------------------CONNECT FLOW WITH OS BY DNS AND UPDATES SERVERS------------------------------'''


def is_win(record):
    return win_reg1.search(record) or win_reg2.search(record) or win_reg3.search(record) \
           or win_reg4.search(record) or win_reg5.search(record) or win_reg6.search(record) \
           or win_reg7.search(record) or win_reg8.search(record) or win_reg9.search(record) \
           or win_reg10.search(record) or win_reg11.search(record) or win_reg12.search(record) \
           or win_reg13.search(record) or win_reg14.search(record) or win_reg15.search(record) \
           or win_reg16.search(record) or win_reg17.search(record) or win_reg18.search(record) \
           or win_reg19.search(record) or win_reg20.search(record) or win_reg21.search(record) \
           or win_reg22.search(record) or win_reg23.search(record) or win_reg24.search(record) \
           or win_reg25.search(record) or win_reg26.search(record) or win_reg27.search(record) \
           or win_reg28.search(record) or win_reg29.search(record) or win_reg30.search(record) \
           or win_reg31.search(record) or win_reg32.search(record) or win_reg33.search(record)

def is_mac(record):
    return mac_reg1.search(record) or mac_reg2.search(record) or mac_reg3.search(record) \
            or mac_reg4.search(record) or mac_reg5.search(record) or mac_reg6.search(record) \
            or mac_reg7.search(record) or mac_reg8.search(record) or mac_reg9.search(record) \
            or mac_reg10.search(record) or mac_reg11.search(record) or mac_reg12.search(record) \
            or mac_reg13.search(record) or mac_reg14.search(record) or mac_reg15.search(record) \
            or mac_reg16.search(record)


def is_lin(record):
    return linux_reg1.search(record) or linux_reg2.search(record) or linux_reg3.search(record)\
           or linux_reg4.search(record) or linux_reg5.search(record) or linux_reg6.search(record)


def is_android(record):
    return android_reg1.search(record) or android_reg2.search(record) or android_reg3.search(record) \
            or android_reg4.search(record) or android_reg5.search(record) or android_reg6.search(record) \
            or android_reg7.search(record) or android_reg8.search(record) or android_reg9.search(record) \
            or android_reg10.search(record) or android_reg11.search(record) or android_reg12.search(record) \
            or android_reg13.search(record) or android_reg14.search(record) or android_reg15.search(record)


def is_fedora(record):
    return fed_reg1.search(record)


def is_blackberry(record):
    return bb_reg1.search(record) or bb_reg2.search(record)


def get_win_version(record):
    if win_version.search(record):
        return win_version.search(record).group(0) + ' '
    return ''


# TODO try find older OS with src port < 5000 in flows, needed more data
def check_os(record):
    if is_win(record):
        return 'Windows'
    if is_mac(record):
        return 'Mac'
    if is_lin(record):
        return 'Linux'
    if is_android(record):
        return 'Android'
    if is_blackberry(record):
        return 'BlackBerry'
    if is_fedora(record):
        return 'Fedora'
    return ''

'''----------------------------------TCP STACK-------------------------------------'''


# get one OS with version and percents from flow record by TCP stack
def calc_os_from_tcp_group(record, raw):
    OS = {}
    total = 0
    for tmp in record.values():
        total += tmp
    for id in record:
        tmp = fingers_dict_id[int(id)]
        for curr_os in tmp:
            curr_os[0] = convert_win_version(curr_os[0])
            if curr_os[0] in OS:
                OS[curr_os[0]] += float(curr_os[1]) * record[id] / total
            else:
                OS[curr_os[0]] = float(curr_os[1]) * record[id] / total
    maxx = 0
    result = None
    # div = 0
    if raw:
        return OS
    for eos in OS:
        # div += float(OS[eos])
        if float(OS[eos]) > maxx:
            result = eos
            maxx = float(OS[eos])
    # maxx = maxx * 100 / div
    return result
    # return result + ', ' + ('%.3f' % round(maxx, 3))


def get_number(line):
    return line.split(';')[6][:-2]


# prepare file for finger_dict calc size of one group
def calc_one_group(group):
    counter = 0
    for record in group:
        counter += int(get_number(record))
    return counter


# prepare file for finger_dict format output
def add_info(size_of_group, group):
    result = []
    for record in group:
        perc = (float(get_number(record)) / float(size_of_group))*100
        prom = (float(get_number(record)) / float(512639568))*1000000
        if perc >= 0.1:
            result.append(record[:-2] + ';' + repr(perc) + ';' + repr(prom) + '\r\n')
    return result


'''-------------------------------------------UA from flow to SESSIONS-------------------------------------------'''


# merge OS with(out) version
def merge_os(record):
    delet = []
    for tmp1 in record:
        delete = False
        for tmp2 in record:
            if tmp1 in tmp2 and tmp1 != tmp2:
                record[tmp2] += record[tmp1]
                delete = True
        if delete:
            delet.append(tmp1)
    for d in delet:
        record.pop(d, None)
    return record

'''--------------------------------RESULTS--------------------------------------------'''
# remove % from record
def remove_UA(array):
    result = ''
    array = array.split(' ')[:-1]
    for tmp in array:
        result += tmp + ' '
    return result


# TODO repair Mac OS X | iOS | Darwin
# return final OS with %

# win_version : name
win_map ={'Windows 10.0': 'Windows 10',
            'Windows 6.3': 'Windows 8.1',
            'Windows 6.2': 'Windows 8',
            'Windows 6.1': 'Windows 7',
            'Windows 6.0': 'Windows Vista',
            'Windows 5.2': 'Windows XP Professional x64',
            'Windows 5.1': 'Windows XP',
            'Windows 5.0': 'Windows 2000'}

def convert_win_version(os):
    if os in win_map:
        return win_map[os]
    return os

def final_os(data):
    if len(data) != 3:
        return ''
    ua = None
    tcp = None
    dns = None

    cou = 0
    if data[0] != {}:
        cou += 1
        ua = data[0]
    if data[1] != {}:
        cou += 1
        tcp = data[1]
    if data[2] != []:
        cou += 1
        dns = data[2]
    if cou == 0:
        return ''

    result = {}

    # add tcp percents
    if tcp != None:
        result = calc_os_from_tcp_group(tcp, True)
        # for tmp in tcp:
        #     result[tmp] = float(tcp[tmp])
        #     total += float(tcp[tmp])

    # add ua percents:
    if ua != None:
        ua_size = 0
        for tmp in ua:
            ua_size += ua[tmp]
        for tmp in ua:
            name = convert_win_version(tmp)
            if tmp in result:
                result[name] += float(100*ua[tmp]/ua_size)
            else:
                result[name] = float(100*ua[tmp]/ua_size)

    # add DNS percents:
    if dns != None:
        for OS in dns:
            if '.' not in OS and OS != '':
                set = False
                for OS_result in result:
                    if OS in OS_result:
                        result[OS_result] += float(100)/len(dns)
                        set = True
                if not set:
                    result[OS] = float(100)/len(dns)
    final_os = ''
    max = 0
    apple = 0
    darwin = 0
    iOS = 0
    Mac = 0
    for OS in result:
        if 'Darwin' in OS:
            apple += result[OS]
            darwin += result[OS]
        elif 'iOS' in OS:
            iOS += result[OS]
            darwin += result[OS]
        elif 'Mac OS X' in OS:
            apple += result[OS]
            Mac += result[OS]
        if result[OS] > max:
            final_os = OS
            max = result[OS]

    if 'Darwin' in final_os or 'iOS' in final_os or 'Mac' in final_os :
        return final_os

    if apple > (max * 5):
        if Mac >= darwin and Mac >= iOS:
            return 'Mac OS X'
        if iOS >= darwin:
            return 'iOS'
        return 'Darwin'
    return final_os
    # return final_os + ', ' + ('%.3f' % (float(max*100)/(cou*100)))


# return final OS without version
def result_only_host_OS(data):
    mac = 0
    win = 0
    linux = 0
    android = 0
    for tmp in data:
        for record in tmp.split(' '):
            OS = delete_major_minor(record)
            if OS == None:
                continue
            if OS == 'Mac':
                mac +=1
            if OS == 'Windows':
                win += 1
            if OS == 'Linux':
                linux +=1
            if OS == 'Android':
                android +=1

    sum = mac + win + linux + android
    if sum == 0:
        return ''
    if mac >= win and mac >= linux and mac >= android :
        return ' ' + repr(100*mac/sum) + ' %'
    if win >= mac and win >= linux and win >= android :
        return ' ' + repr(100*win/sum) + ' %'
    if linux >= win and mac <= linux and linux >= android:
        return ' ' + repr(100*linux/sum) + ' %'
    if android >= win and android >= linux and mac <= android:
        return ' ' + repr(100*android/sum) + ' %'

    return ''


# remove version from OS
def delete_major_minor(record):
    if 'Mac' in record or 'iOS' in record or 'Darwin' in record or 'OS X' in record:
        return 'Mac'
    if 'Win' in record:
        return 'Windows'
    if 'Debian' in record or 'Ubuntu' in record or 'Fedora' in record or 'Linux' in record:
        return 'Linux'
    if 'Android' in record:
        return 'Android'
    return None


'''--------------------------------------------------DHCP------------------------------------------------------'''

# N/A for desktop
#  '' for devices without name
def get_OS_from_device_name(line):
    if 'MacBook' in line or 'macbook' in line:
        return 'Mac OS X'
    if 'iPhone' in line or 'Iphone' in line or 'iPad' in line or 'iPod' in line:
        return 'iOS'
    if 'Windows-phone' in line or 'windows-phone' in line:
        return 'Windows Phone'
    if 'windows' in line or 'Windows' in line:
        return 'Windows'
    if ('pc' not in line and 'PC' not in line) and ('android' in line or 'Android' in line or 'samsung' in line or 'Samsung' in line  or 'Galaxy' in line or 'HUAWEI' in line \
            or 'Honor' in line or 'honor' in line or 'Xiaomi' in line or 'Redmi' in line):
        return 'Android'
    if 'BLACKBERRY' in line:
        return 'BlackBerry'
    return ''

hwaddr_reg = re.compile('(?:[0-9a-f]{2}:){5}[0-9a-f]{2}')
hwaddr_time_reg = re.compile('\d \d\d:\d\d:\d\d')
hwaddr_name_reg = re.compile('\(.*\)')

def get_mac(string):
    return hwaddr_reg.search(string).group(0)


def get_dhcp_time(string):
    if "Apr 30 " in string:
        return ''
    return '2017-05-0' + hwaddr_time_reg.search(string).group(0)


def create_DHCP_dict():
    with open(dhcp_path, 'r') as dhcp:
        result = {}
        for line in dhcp:
            OS = get_OS_from_device_name(line)
            time = get_dhcp_time(line)
            if time != '':
                name = ''
                if hwaddr_name_reg.search(line):
                    name = hwaddr_name_reg.search(line).group(0)
                # time = (datetime.datetime.strptime(time, "%Y-%m-%d %H:%M:%S") + datetime.timedelta(seconds=5)).strftime("%Y-%m-%d %H:%M:%S")
                ip = get_ip(line)
                # if len(get_all_ip(line)) == 2:
                #     ip2 = get_all_ip(line)[1]
                # else:
                #     ip2 = ''
                mac = get_mac(line)
                if ip not in result:
                    result[ip] = {}
                    result[ip] = [[time, time, OS, mac, name]]
                elif result[ip][-1][3] != mac or result[ip][-1][2] != OS:
                        result[ip].append([time, time, OS, mac, name])
                # elif result[ip][-1][2] == '' and OS != '':
                #     result[ip][-1] = [result[ip][-1][0], time, OS, mac, ip2]
                else:
                    result[ip][-1] = [result[ip][-1][0], time, result[ip][-1][2], mac, name]
        return result


def create_url_map():
    with open('FINAL/aktualne/idk.csv', 'r') as idk_in:
        with open('FINAL/aktualne/idk_domain.csv', 'w') as idk_out:
            result = {}
            idk_in.readline()
            for line in idk_in:
                array = line.split(';')[:-1]
                # if int(array[3]) < 100:
                #     continue
                url = array[0].split(',')[7][2:-1]
                idk_out.write(url + ';' + array[1] + ';' + array[2] + ';' + array[3] + '\n')



def aggregate_url_map():
    with open('FINAL/aktualne/idk_domain.csv', 'r') as idk_in:
        with open('FINAL/aktualne/idk_domain_out.csv', 'w') as idk_out:
            result_dict = {}
            for line in idk_in:
                array = line.split(';')
                url = array[0]
                os = array[1]
                size = int(array[3][:-1])
                if url not in result_dict:
                    result_dict[url] = {}
                if os not in result_dict[url]:
                    result_dict[url][os] = size
                else:
                    result_dict[url][os] += size

            for url in result_dict:
                max = 0
                counter = 0
                final_OS = None
                for OS in result_dict[url]:
                    counter += result_dict[url][OS]
                    if result_dict[url][OS] > max:
                        max = result_dict[url][OS]
                        final_OS = OS
                if max >= 100 and counter < max * 2:
                    idk_out.write(url + ';' + final_OS + ';' + repr(max) + ';' + repr(float(max)/counter) + ';\r\n')


# create_url_map()
# aggregate_url_map()

def create_dhcp_dict_file():
    with open('FINAL/DHCP_dict.csv', 'w') as output:
        for ip in dhcp_dict:
            for record in dhcp_dict[ip]:
                output.write(ip + ';' + record[0] + ';' + record[1] + ';' + record[2] + ';' + record[3] +  ';' + record[4] + ';\n')


def load_DHCP_dict():
    with open(dhcp_path, 'r') as dhcp:
        result = {}
        for line in dhcp:
            array = line.split(';')[:-1]
            if array[0] not in result:
                result[array[0]] = {}
                result[array[0]] = [array[1:]]
            else:
                result[array[0]].append(array[1:])
        return result


def load_time_dict():
    with open(time_path, 'r') as time:
        result = {}
        for line in time:
            array = line.split(';')
            result[array[0]] = array[1]

        return result

# def tmp():
#     with open('FINAL/sessions_full_extended.csv', 'r') as input:
#         with open('FINAL/sessions_full_extended_out.csv', 'w') as output:
#             output.write(input.readline())
#             for line in input:
#                 if line.split(';')[17] != '':
#                     output.write(line)
#
# tmp()
'''---------------------------------------GLOBAL-----------------------------------------------------'''
# time_dict = load_time_dict()
# dhcp_dict = load_DHCP_dict()
fingers_dict = create_fingers_dict()
# sessions_dict = create_session_dict_by_ip()
# sessions_dict_with_os = create_session_dict_by_id_OS()
# sessions_dict_id = create_session_dict_by_id()
fingers_dict_id = create_fingers_dict_id()
# eduroam_dict = create_eduroam_dict()
# eduroam_name_dict = create_eduroam_with_names_dict()
# mac_dict = create_session_id_to_mac_dict()

# create_dhcp_dict_file()
# create_time_skeleton()
# save_idk()
# load_idk_fingers()

