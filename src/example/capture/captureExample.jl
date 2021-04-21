include("../../JPcap.jl")
using .JPcap

handle = pcap_open_offline("TeamSpeak2.pcap");

header = Ref{Pcap_pkthdr}()

count = 0
while true
    try
        packet = pcap_next(handle, header)        
        global count += 1

        println("Packet ", count)

        iph = Ipv4Hdr(packet)
        println("Got a packet from ", uint32_to_inet(iph.src_ip),
                    " going to ", uint32_to_inet(iph.dest_ip))
    catch
        break
    end
end
