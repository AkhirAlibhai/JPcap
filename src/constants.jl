export PCAP_ERRBUF_SIZE,
        PCAP_NETMASK_UNKNOWN,
        PCAP_ERROR, PCAP_WARNING

const PCAP_ERRBUF_SIZE = 256

const PCAP_NETMASK_UNKNOWN = 0xffffffff

#=
    Error codes for the pcap API
=#
const PCAP_ERROR = -1                   # generic error code
const PCAP_ERROR_ACTIVATED = -4         # the operation can't be performed on already activated captures
const PCAP_ERROR_NO_SUCH_DEVICE = -5	# no such device exists
const PCAP_ERROR_RFMON_NOTSUP = -6	    # this device doesn't support rfmon (monitor) mode
const PCAP_ERROR_PERM_DENIED = -8	    # no permission to open the device
const PCAP_ERROR_IFACE_NOT_UP = -9      # interface isn't up

#=
    Warning codes for the pcap API
=#
const PCAP_WARNING = 1                  # generic warning code
const PCAP_WARNING_PROMISC_NOTSUP = 2	# this device doesn't support promiscuous mode

#=
    ARP protocol HARDWARE identifiers
=#
const ARPHRD_NETROM = 0         # From KA9Q: NET/ROM pseudo
const ARPHRD_ETHER = 1          # Ethernet 10/100Mbps
const ARPHRD_EETHER = 2         # Experimental Ethernet
const ARPHRD_AX25 = 3           # AX.25 Level 2
const ARPHRD_PRONET = 4         # PROnet token ring
const ARPHRD_CHAOS = 5          # Chaosnet
const ARPHRD_IEEE802 = 6        # IEEE 802.2 Ethernet/TR/TB
const ARPHRD_ARCNET = 7         # ARCnet
const ARPHRD_APPLETLK = 8       # APPLEtalk
const ARPHRD_DLCI = 15          # Frame Relay DLCI
const ARPHRD_ATM = 19           # ATM
const ARPHRD_METRICOM = 23	    # Metricom STRIP (new IANA id)
const ARPHRD_IEEE1394 = 24      # IEEE 1394 IPv4 - RFC 2734
const ARPHRD_EUI64 = 27         # EUI-64
const ARPHRD_INFINIBAND = 32    # InfiniBand

#=
    ARP protocol opcodes
=#
const ARPOP_REQUEST = 1     # ARP request
const ARPOP_REPLY = 2       # ARP reply
const ARPOP_RREQUEST = 3    # RARP request
const ARPOP_RREPLY = 4      # RARP reply
const ARPOP_InREQUEST = 8   # InARP request
const ARPOP_InREPLY = 9     # InARP reply
const ARPOP_NAK = 10        # (ATM)ARP NAK

#=
    Ethernet magic constants
=#
const ETH_ALEN = 6                      # Octets in one ethernet addr
const ETH_TLEN = 2                      # Octets in ethernet type field
const ETH_HLEN = 14                     # Total octets in header
const ETH_ZLEN = 60                     # Min. octets in frame sans FCS
const ETH_DATA_LEN = 1500               # Max. octets in payload
const ETH_FRAME_LEN = 1514              # Max. octets in frame sans FCS
const ETH_FCS_LEN = 4                   # Octets in the FCS

const ETH_MIN_MTU = 68                  # Min IPv4 MTU per RFC791
const ETH_MAX_MTU = unsigned(0xFFFF)    # 65535, same as IP_MAX_MTU

#=
    Ethernet protocol ID's
=#
const ETHERTYPE_PUP = 0x0200        # Xerox PUP
const ETHERTYPE_SPRITE = 0x0500     # Sprite
const ETHERTYPE_IP = 0x0800         # IP
const ETHERTYPE_ARP = 0x0806        # Address resolution
const ETHERTYPE_REVARP = 0x8035     # Reverse ARP
const ETHERTYPE_AT = 0x809B         # AppleTalk protocol
const ETHERTYPE_AARP = 0x80F3       # AppleTalk ARP
const ETHERTYPE_VLAN = 0x8100       # IEEE 802.1Q VLAN tagging
const ETHERTYPE_IPX = 0x8137        # IPX
const ETHERTYPE_IPV6 = 0x86dd       # IP protocol version 6
const ETHERTYPE_LOOPBACK = 0x9000   # used to test interfaces

const ETHER_ADDR_LEN = ETH_ALEN                         # size of ethernet addr
const ETHER_TYPE_LEN = 2                                # bytes in type field
const ETHER_CRC_LEN = 4                                 # bytes in CRC field
const ETHER_HDR_LEN = ETH_HLEN                          # total octets in header
const ETHER_MIN_LEN = (ETH_ZLEN + ETHER_CRC_LEN)        # min packet length
const ETHER_MAX_LEN = (ETH_FRAME_LEN + ETHER_CRC_LEN)   # max packet length

#=
    IP protocol numbers
=#
export IP_TCP, IP_UDP

const IP_TCP = 6        # Transmission Control Protocol
const IP_UDP = 17       # User Datagram Protocol
