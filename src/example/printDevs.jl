include("../JPcap.jl")
using .JPcap

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
