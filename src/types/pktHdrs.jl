export pcap_pkthdr

"""
    A time value that is accurate to the nearest
    microsecond but also has a range of years.
"""
struct timeval
    tv_sec::Clong   # Seconds
    tv_usec::Clong  # Microseconds
end

struct pcap_pkthdr
	ts::timeval 	# time stamp
	caplen::Int32   # length of portion present
	len::Int32      # length this packet (off wire)
end
