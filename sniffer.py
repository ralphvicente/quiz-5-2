from scapy.all import Packet, Ether, IP, ICMP, Raw, sniff, send

def main():
    """Driver function"""
    while True:
        print_menu()
        option : str = input('Choose a menu option: ')
        if option == '1':
            number : int = int(input("Number of packets to be sent: "))
            interval : int = int(input("Number of seconds between each packet: "))
            print("Creating and sending packets ...")
            send_pkt(number, interval)
        elif option == '2':
            print("Listening to all traffic and show all ...")
            capture = sniff(prn= lambda x: x.show(), iface='eth0')
        elif option == '3':
            print("Listening to ping command to the address 8.8.4.4 ...")
            capture = sniff(prn= lambda x: print_pkt(x), filer='icmp and dst 8.8.4.4')
        elif option == '4':
            print("Listening to telnet command executed from localhost ...")
            capture = sniff(prn= lambda x: print_pkt(x), filter='tcp and src 127.0.0.1')
        elif option == '5':
            print("End")
            break
        else:
            print(f"\nInvalid entry\n")


"""
@brief      Creates and sends multilayer packet
@param      number: int     number of packets to be sent 
@param      interval: int   the number of seconds between each packet
"""
def send_pkt(number:int, interval:int) -> None:
    Ethernet_Layer : Ether = Ether(src='00:ae:f3:52:aa:d1', dst='00:02:15:37:a2:44')
    IP_Layer : IP = IP(src='192.168.10.4', dst='192.168.6.12', ttl=32)
    ICMP_Layer : ICMP = ICMP(type='echo-request')
    Payload : str = "CSCE 313 secret message"

    pkt : Packet = IP_Layer/ICMP_Layer/Payload

    pkt.show()

    send(pkt, inter=interval, count=number)


"""
@brief      Prints out packet information
@param      pkt: Packet                     packet to be printed
"""
def print_pkt(pkt):
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