-- MOEX FIX/FAST simplified dissector
-- 
-- Version: 0.1
-- Author: Serov Aleksandr
--
-- This dissector is useful only for problem detection. It analyzes MsgSeqNum, 
-- find losses and duplications.
--
-- Results of analysis is placed in moexfast.diag
--      moexfast.diag == 0     -- no problem
--      moexfast.diag == 1     -- some losses before this packet
--      moexfast.diag == 2     -- duplicated packet
--
-- To find problems you can use display filter "moexfast.diag > 0"
--
-- The list of UDP port is defined in botton of this script. To add additional ports you 
-- can add to the bottom of this file something like:
--for i = 27101, 27199, 1 do
--	udp_encap_table:add(i,p_mfast)
--end
--
--  Windows installation:
-- 	1. Check that the LUA is enabled. File /Proramm files/wireshark/init.lua should 
--     contains the string "disable_lua = false"
--  2. Place this file to folder /Proramm files/wireshark/plugins/<version number>/
--

local sp = {}
local pn = {}

local p_mfast = Proto("moexfast", "MOEX FIX/FAST UDP (simple)");

local F_seq   = ProtoField.uint32("moexfast.seq", "Sequence", base.DEC)
local F_psq   = ProtoField.uint32("moexfast.psq", "Prev-seq", base.DEC)
local F_diag  = ProtoField.uint8("moexfast.diag", "Seq diag", base.DEC)

p_mfast.fields = { F_seq, F_psq, F_diag }

function p_mfast.dissector(buf,pkt,root)
	if buf:len() == 0 then return end
	pkt.cols.protocol = p_mfast.name

	port = pkt.dst_port
	if sp[port]==nil then sp[port] = 0 end
	curseq = buf(0,3):le_uint()

	if not pkt.visited then
		pn[pkt.number] = sp[port]
	end

	sp[port] = curseq

	failedval = 0

	if (pn[pkt.number]==nil) then 
		pn[pkt.number] = 0
	end
	if (curseq > (pn[pkt.number] + 1) and pn[pkt.number]~=0 ) then
		failedval = 1
	end
	if (curseq == pn[pkt.number]) then
		failedval = 2
	end
	
	local t = root:add(p_mfast, buf())
	t:add(F_psq, pn[pkt.number])
	t:add(F_seq, curseq)
	t:add(F_diag, buf(), failedval) 
	pkt.cols.info = "Dst port:" .. port .. " seq:" .. string.format("%u",curseq) .. " fail:" .. failedval
	if ( failedval==1 ) then
   	pkt.cols.info = "Dst port:" .. port .. " seq:" .. string.format("%u",curseq) .. " fail:" 
   	                 .. failedval .. " frame lost:" .. (curseq-pn[pkt.number]-1)
	end
	if ( failedval==2 ) then
   	pkt.cols.info = "Dst port:" .. port .. " seq:" .. string.format("%u",curseq) .. " fail:" 
   	                 .. failedval .. " Duplacate!!!"
	end
		
end

local udp_encap_table = DissectorTable.get("udp.port")

-- currency market
for i = 16001, 16010, 1 do
	udp_encap_table:add(i,p_mfast)
	udp_encap_table:add(i+1000,p_mfast)
end

-- stock market
for i = 16041, 16050, 1 do
	udp_encap_table:add(i,p_mfast)
	udp_encap_table:add(i+1000,p_mfast)
end

-- FORTS-RTSX
for i = 26001, 26052, 1 do
	udp_encap_table:add(i,p_mfast)
	udp_encap_table:add(i+1000,p_mfast)
end

-- FORTS-ETSC
for i = 26151, 26185, 1 do
	udp_encap_table:add(i,p_mfast)
	udp_encap_table:add(i+1000,p_mfast)
end
