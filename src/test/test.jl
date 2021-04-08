include("../jPcap.jl")
using .jPcap

"""
    Print all capture devices on the device 
"""
function print_all_devs()::Nothing
    devs = pcap_findalldevs()
    j_devs = j_pcap_if_t(devs)
    
    println("Capture devices on this device are:")

    while j_devs != nothing
        println(j_devs.name)

        j_devs = j_devs.next
    end

    pcap_freealldevs(devs)

    return nothing
end

print_all_devs()

devs = pcap_findalldevs()
name = j_pcap_if_t(devs).name
pcap_freealldevs(devs)

# Opens a handle with the first capture device
handle = pcap_open_live(name, 0, 1, 100)

# Garbage packet being made
packet = Array{Cuchar}(undef, 100)
for x in 1:6
    packet[x] = 1
end

for x in 7:12
    packet[x] = 2
end

for x in 13:100
    packet[x] = x
end

# Sends the garabge packet
ret = pcap_sendpacket(handle, Ptr{UInt8}.(Base.pointer_from_objref(packet)), 100)

# Defining a callback function for capturing packets
function callback(user::UInt8, h::Ptr{pcap_pkthdr}, packet::Ptr{UInt8})::Cvoid
    # Need to skip the Ethernet header
    pkt = unsafe_load(Ptr{Ipv4Hdr}(packet + sizeof(EtherHdr)))
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

# Compiling the callback
callback_c =  @cfunction(callback, Cvoid, (UInt8, Ptr{pcap_pkthdr}, Ptr{UInt8}))

# Capturing a packet
ret = pcap_loop(handle, 1, callback_c, C_NULL)
