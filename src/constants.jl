export PCAP_ERRBUF_SIZE,
       PCAP_NETMASK_UNKNOWN,
       PCAP_ERROR, PCAP_WARNING,
       ARPHRD_ID, ARPOP, ETH_MAGIC,
       ETHERTYPE_ID, IP_NUM

PCAP_ERRBUF_SIZE = 256

PCAP_NETMASK_UNKNOWN = 0xffffffff

#=
    Error codes for the pcap API
=#
PCAP_ERROR = (
    PCAP_ERROR = -1,                    # generic error code
    PCAP_ERROR_ACTIVATED = -4,          # the operation can't be performed on already activated captures
    PCAP_ERROR_NO_SUCH_DEVICE = -5,	    # no such device exists
    PCAP_ERROR_RFMON_NOTSUP = -6,	    # this device doesn't support rfmon (monitor) mode
    PCAP_ERROR_PERM_DENIED = -8,	    # no permission to open the device
    PCAP_ERROR_IFACE_NOT_UP = -9,       # interface isn't up
)

#=
    Warning codes for the pcap API
=#
PCAP_WARNING = (
    PCAP_WARNING = 1,                   # generic warning code
    PCAP_WARNING_PROMISC_NOTSUP = 2,    # this device doesn't support promiscuous mode
)

#=
    ARP protocol HARDWARE identifiers
=#
ARPHRD_ID = (
    ARPHRD_NETROM = 0,          # From KA9Q: NET/ROM pseudo
    ARPHRD_ETHER = 1,           # Ethernet 10/100Mbps
    ARPHRD_EETHER = 2,          # Experimental Ethernet
    ARPHRD_AX25 = 3,            # AX.25 Level 2
    ARPHRD_PRONET = 4,          # PROnet token ring
    ARPHRD_CHAOS = 5,           # Chaosnet
    ARPHRD_IEEE802 = 6,         # IEEE 802.2 Ethernet/TR/TB
    ARPHRD_ARCNET = 7,          # ARCnet
    ARPHRD_APPLETLK = 8,        # APPLEtalk
    ARPHRD_DLCI = 15,           # Frame Relay DLCI
    ARPHRD_ATM = 19,            # ATM
    ARPHRD_METRICOM = 23,	    # Metricom STRIP (new IANA id)
    ARPHRD_IEEE1394 = 24,       # IEEE 1394 IPv4 - RFC 2734
    ARPHRD_EUI64 = 27,          # EUI-64
    ARPHRD_INFINIBAND = 32      # InfiniBand
)

#=
    ARP protocol opcodes
=#
ARPOP = (
    ARPOP_REQUEST = 1,      # ARP request
    ARPOP_REPLY = 2,        # ARP reply
    ARPOP_RREQUEST = 3,     # RARP request
    ARPOP_RREPLY = 4,       # RARP reply
    ARPOP_InREQUEST = 8,    # InARP request
    ARPOP_InREPLY = 9,      # InARP reply
    ARPOP_NAK = 10          # (ATM)ARP NAK
)

#=
    Ethernet magic constants
=#
ETH_MAGIC = (
    ETH_ALEN = 6,                    # Octets in one ethernet addr
    ETH_TLEN = 2,                    # Octets in ethernet type field
    ETH_HLEN = 14,                   # Total octets in header
    ETH_ZLEN = 60,                   # Min. octets in frame sans FCS
    ETH_DATA_LEN = 1500,             # Max. octets in payload
    ETH_FRAME_LEN = 1514,            # Max. octets in frame sans FCS
    ETH_FCS_LEN = 4,                 # Octets in the FCS

    ETH_MIN_MTU = 68,                # Min IPv4 MTU per RFC791
    ETH_MAX_MTU = unsigned(0xFFFF)   # 65535, same as IP_MAX_MTU
)

#=
    Ethernet protocol ID's
=#
ETHERTYPE_ID = (
    ETHERTYPE_PUP = 0x0200,                                 # Xerox PUP
    ETHERTYPE_SPRITE = 0x0500,                              # Sprite
    ETHERTYPE_IP = 0x0800,                                  # IP
    ETHERTYPE_ARP = 0x0806,                                 # Address resolution
    ETHERTYPE_REVARP = 0x8035,                              # Reverse ARP
    ETHERTYPE_AT = 0x809B,                                  # AppleTalk protocol
    ETHERTYPE_AARP = 0x80F3,                                # AppleTalk ARP
    ETHERTYPE_VLAN = 0x8100,                                # IEEE 802.1Q VLAN tagging
    ETHERTYPE_IPX = 0x8137,                                 # IPX
    ETHERTYPE_IPV6 = 0x86dd,                                # IP protocol version 6
    ETHERTYPE_LOOPBACK = 0x9000,                            # used to test interfaces

    ETHER_ADDR_LEN = ETH_MAGIC.ETH_ALEN,                    # size of ethernet addr
    ETHER_TYPE_LEN = 2,                                     # bytes in type field
    ETHER_CRC_LEN = 4,                                      # bytes in CRC field
    ETHER_HDR_LEN = ETH_MAGIC.ETH_HLEN,                     # total octets in header
    ETHER_MIN_LEN = (ETH_MAGIC.ETH_ZLEN + 4),               # min packet length
    ETHER_MAX_LEN = (ETH_MAGIC.ETH_FRAME_LEN + 4)           # max packet length
)

#=
    IP protocol numbers
=#
IP_NUM = (
    IP_TCP = 6,     # Transmission Control Protocol
    IP_UDP = 17     # User Datagram Protocol
)
