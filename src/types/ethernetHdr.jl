include("../constants.jl")
include("linkHdrs.jl")

export EtherAddr, EtherHdr,
        EtherArp, EtherPkt

struct EtherAddr
    ether_addr_octet::NTuple{ETH_MAGIC.ETH_ALEN, Cuchar}
end

struct EtherHdr
    ether_dhost::NTuple{ETH_MAGIC.ETH_ALEN, Cuchar}     # Destination eth addr
    ether_shost::NTuple{ETH_MAGIC.ETH_ALEN, Cuchar}     # Source ether addr
    ether_type::Cushort                                 # Packet type ID field
end

abstract type EtherPayload end

struct EtherArp <: EtherPayload
    ea_hdr::ArpHdr                                  # Fixed-size header
    arp_sha::NTuple{ETH_MAGIC.ETH_ALEN, Cuchar}     # Sender hardware address
    arp_spa::NTuple{4, Cuchar}                      # Sender protocol address
    arp_tha::NTuple{ETH_MAGIC.ETH_ALEN, Cuchar}     # Target hardware address
    arp_tpa::NTuple{4, Cuchar}                      # Target protocol address
end

struct EtherPkt
    hdr::EtherHdr
    paylod::EtherPayload
end
