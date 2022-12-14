from scapy.all import Packet, Ether, IP, ICMP, Raw, sniff, sendp

def main():
    """Driver function"""
    while True:
        print_menu()
        option : str = input('Choose a menu option: ')
        if option == '1':
            number = int(input("Number of packets to be sent: "))
            interval = int(input("Number of seconds between each packet: "))
            print("Creating and sending packets ...") 
            send_pkt(number, interval)
        elif option == '2':
            print("Listening to all traffic and show all ...")
            sniff(iface='br-d1f057009f5d', prn= lambda x: x.show) 
        elif option == '3':
            print("Listening to ping command to the address 8.8.4.4 ...")
            sniff(filter='icmp and dst 8.8.4.4' ,prn= lambda x: print_pkt(x))
        elif option == '4':
            print("Listening to telnet command executed from localhost ...")
            sniff(filter='tcp and src 127.0.0.1', prn= lambda x: print_pkt(x))
        elif option == '5':
            print("End")
            break
        else:
            print(f"\nInvalid entry\n")



def send_pkt(number : int, interval : int):
    """Send a custom packet"""
    #TODO
    payload = 'CSCE 313 secret message'

    pkt = IP(src='192.168.10.4', dst='192.168.6.12', ttl=32) / ICMP(type='echo-request') / payload

    #pkt.show() #used to confirm packet

    sendp(pkt, inter=interval, count=number)


def print_pkt(pkt):
    """ Print Source IP, Destination IP, Protocol, TTL"""
    # TODO
    print()
    print("Source IP: ", pkt.src)
    print("Destination IP: ", pkt.dst)
    print("Protocol: ", pkt.proto)
    print("TTL: ", pkt.ttl)
    


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