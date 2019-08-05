# FAST_dissector
Simple wireshark dissector. Allows to find sequence gaps in FAST flow
 
 This dissector is useful only for problem detection. It analyzes only MsgSeqNum, 
 find losses and duplications.

 Results of analysis is placed in moexfast.diag

      moexfast.diag == 0     -- no problem
      moexfast.diag == 1     -- some losses before this packet
      moexfast.diag == 2     -- duplicated packet

 To find problems you can use display filter "moexfast.diag > 0"

 The list of UDP port is defined in bottom of this script. To add additional ports you 
 can add to the bottom of this file something like:

```
for i = 27101, 27199, 1 do
	udp_encap_table:add(i,p_mfast)
end
```

# Windows installation:
  1. Check that the LUA is enabled. File /Proramm files/wireshark/init.lua should 
     contains the string "disable_lua = false"
  2. Place this file to folder /Proramm files/wireshark/plugins/<version number>/

