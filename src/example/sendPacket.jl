include("../jPcap.jl")
using .jPcap

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
if ret == 0
    println("Packet sent successfully")
else
    println("Packet not sent")
    pcap_perror(handle)
end
