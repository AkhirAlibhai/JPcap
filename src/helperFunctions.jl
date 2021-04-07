export htons, inet_to_uint32,
        iface_to_mac

function htons(hostshort::Int64)::Cushort
    ccall(:htons, Cushort, (Cushort,), convert(UInt16, hostshort))
end

struct in_addr
    s_addr::Cuint
end

function inet_to_uint32(string::String)::UInt32
    addr = Ref{in_addr}()

    if ccall(:inet_aton, Int32, (Cstring, Ref{in_addr}), string, addr) == 0
        throw(error(string, " is not a valid IP address"))
    end

    addr[].s_addr
end


const IF_NAMESIZE = 16

const IFHWADDRLEN = 6
const IFNAMSIZ = IF_NAMESIZE

mutable struct ifreq
    ifrn_name::NTuple{IFNAMSIZ, Cuchar}
    ifr_ifru::NTuple{IF_NAMESIZE, Cuchar}
    # Union of ifr_ifru:
    #   struct sockaddr ifru_addr
    #   struct sockaddr ifru_dstaddr
    #   struct sockaddr ifru_broadaddr
    #   struct sockaddr ifru_netmask
    #   struct sockaddr ifru_hwaddr
    #   short int ifru_flags
    #   int ifru_ivalue
    #   int ifru_mtu
    #   struct ifmap ifru_map
    #   char ifru_slave[IFNAMSIZ]
    #   char ifru_newname[IFNAMSIZ]
end


const PF_INET = 2           # IP protocol family
const AF_INET = PF_INET

const SOCK_DGRAM = 2        # Connectionless, unreliable datagrams of fixed maximum length

const SIOCGIFADDR = 0x8915      # get PA address

# TODO: Finish and clean this up
function iface_to_mac(iface::String)
    if length(iface) > IFNAMSIZ
        throw(error("Interface name is too long"))
    end

    name = ntuple(i -> UInt8(i > length(iface) ? 0 : iface[i]), IFNAMSIZ)

    ifr = Ref{ifreq}(ifreq(name, name))

    fd = ccall(:socket, Int32, (Int32, Int32, Int32), AF_INET, SOCK_DGRAM, 0)
    ret = ccall(:ioctl, Int32, (Int32, Culong, Ref{ifreq}), fd, SIOCGIFADDR, ifr)

    ccall(:close, Int32, (Int32,), fd)
end
