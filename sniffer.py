from scapy.all import *


def main():
    """Driver function"""
    while True:
        print_menu()
        option = input('Choose a menu option: ')
        if option == '1':
            print("Creating and sending packets ...")
            # TODO
        elif option == '2':
            print("Listening to all traffic and show all ...")
            # TODO
        elif option == '3':
            print("Listening to ping command to the address 8.8.4.4 ...")
            # TODO
        elif option == '4':
            print("Listening to telnet command executed from localhost ...")
            # TODO
        elif option == '5':
            print("End")
            break
        else:
            print(f"\nInvalid entry\n")

def send_pkt(number, interval):
    """Send a custom packet"""
    # TODO
    pass

def print_pkt(pkt):
    """ Print Source IP, Destination IP, Protocol, TTL"""
    # TODO
    pass


def print_menu():
    """Prints the menu of options"""
    print("*******************Main Menu*******************")
    print('1. Create and send packets')
    print('2. Listen to all traffic and show all')
    print('3. Listen to ping command to the address 8.8.4.4')
    print('4. Listen to telnet command executed from localhost')
    print('5. Quit')
    print('***********************************************\n')


main()
