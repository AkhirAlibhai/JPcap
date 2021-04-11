include("../jPcap.jl")
using .jPcap

devs = pcap_findalldevs()
name = j_pcap_if_t(devs).name
pcap_freealldevs(devs)

# Opens a handle with the first capture device
handle = pcap_open_live(name, 0, 1, 100)

# Defining a callback function for capturing packets
function callback(user::UInt8, h::Ptr{pcap_pkthdr}, packet::Ptr{UInt8})::Cvoid
    # Need to skip the Ethernet header
    pkt = unsafe_load(Ptr{Ipv4Hdr}(packet + sizeof(EtherHdr)))

    println("Got packet from ", uint32_to_inet(pkt.src_ip), " going to ", uint32_to_inet(pkt.dest_ip))
    return nothing
end

# Only detecting packets from "www.google.com"
program = Ref{bpf_program}()
ret = pcap_compile(handle, program, "host www.google.com", 1, PCAP_NETMASK_UNKNOWN)

if ret == -1
    println("Broke on compile")
    println(ret)
    pcap_perror(handle)
    exit()
end

ret = pcap_setfilter(handle, program)
if ret == -1
    println("Broke on set")
    println(ret)
    pcap_perror(handle)
    exit()
end

pcap_freecode(program)

# Capturing a packet
ret = pcap_loop(handle,
                    1,
                    @cfunction(callback, Cvoid, (UInt8, Ptr{pcap_pkthdr}, Ptr{UInt8})),
                    C_NULL)
