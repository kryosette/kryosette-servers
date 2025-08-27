# 5. Compliance with the standard (Conformity)
## 5.1 Mandatory requirements

**A MAC bridge conforming to this standard MUST:**
a) Comply with MAC technology standards on its ports.
b) Maintain LLC (Logical Link Control) in accordance with IEEE Std 802.2.
c) Relay and filter frames (this is his main job!).
d) Maintain information for basic filtering services.
e) Comply with the addressing rules.
f) Implement Rapid Spanning Tree Protocol (RSTP). 
g) Work correctly with BPDU.
h) Have documented parameters (size of the MAC address table, etc.).
i) Have documented performance characteristics (filtering rate, forwarding rate).


## 5.2 Optional features

**A bridge CAN (but is not required to):**
a) Support a management system (e.g. via SNMP).
b) Support remote management.
c) Maintain quality of service (QoS) and multiple traffic classes.
d) Support advanced filtering services (e.g. GMRP for efficient handling of multicast traffic).