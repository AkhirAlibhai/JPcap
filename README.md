# Julia Packet Library - COMP 4905 Honours Project

## Purpose

To create a library that allows crafting and sniffing of packets in Julia.

# Dependencies

- julia
- libpcap-dev

# libpcap repository

https://github.com/the-tcpdump-group/libpcap

# Rewrite Information

I now realize that a lot of the functions don't really make sense. They just wrap C code and should instead convert them to Julia-like objects that are easier to interact with.
Starting to fix that, so things will be super broken on this branch until then.

# To Do list

- [x] View Interfaces on device
- [x] Intial packet structure
- [x] Intial creation process of packets
- [x] Intial sending process of packets
- [x] Intial sniffing process of packets
- [x] Constructors for packets
- [ ] Finish creation process of packets
- [x] Finish sending process of packets
- [x] Finish sniffing process of packets
- [ ] Import pcapng files and parse packets
- [ ] Export sniffed packets as pcapng file
- [x] Reformat all the files so that they actually make sense
- [ ] Performance testing (Elaborate more on this)
- [ ] Add actual valuable information to this README
- [ ] REFORMAT EVERYTHING BECAUSE IT'S SO CLUNKY