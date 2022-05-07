# MyTracert
Program to trace a packet's way through the internet from its source to its destination.
---
Should work similar to traceroute (Linux) / tracert (Windows).

Mechanism:
A UDP packet with a low TTL (time to live) is sent to the destination.\
Each hop (a server or whatever) on the way decreases the TTL.\
When the TTL has reached 0 the hop usually sends us an ICMP packet with type 'time exceeded' (11)
and our original UDP packet inside it.\
So to trace a packet's way we start by sending UDP packets in the aforementioned way and extract
the sender's IP address from the incoming ICMP packet.\
We start with a TTL of 1 and than increment it in each iteration.\
The problems are:
- We don't know if an incoming ICMP packet was really sent from one of the hops or if it
  is unrelated. So we check the copy of the UDP packet we originally sent which is contained in
  the ICMP packet. But the data we sent along isn't always present, so we check if the lengths
  of the UDP packets match.
- Not every hop sends an ICMP packet back to us. So we try again till we can be sure we haven't
  missed anything.
