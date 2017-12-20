#!/usr/bin/python
import usb.core
from hashlib import sha256
from getopt import getopt
from binascii import crc32, hexlify
from struct import pack,unpack
import sys
from time import sleep
import gzip

BLK=512

def detect_dev():
	global dev
	dev = usb.core.find(idVendor=0x0fce,idProduct=0xadde)
	if dev is None:
		return False
	print("\tFound usb dev: %s,%s"%(dev.manufacturer,dev.product))
	return True

sumtbl = [0 for i in range(0x100)]
for i in range(256):
	l1 = i
	for j in range(8):
		if l1 & 1:
			l1 = (l1 >> 1 ^ 0xedb88320) & 0xffffffff;
		else:
			l1 = (l1 >> 1) & 0xffffffff
	sumtbl[i] = l1

def calc_data_checksum(data,res=0):
	for b in map(ord,data):
		l = (res ^ b)
		res = (res >> 8) ^ sumtbl[l & 0xff]
	return pack(">I", res)

def calc_hdr_checksum(hdr,s=0):
	for b in hdr:
		s ^= ord(b)
	return chr(0xff & (s+7))

def read_block(n=BLK,timeout=-1):
	return "".join(map(chr,dev.read(0x81,n,timeout=timeout)))

def write_block(blk):
	assert(len(blk)==dev.write(1,blk,timeout=-1))

def read_packet(timeout=-1):
	d=read_block(13,timeout)
	assert(len(d) == 13)
	if calc_hdr_checksum(d[:12]) != d[12]:
		print( "Error: Bad header checksum")
		exit(1)
	cmd,flag,size,c = unpack(">IIIB",d)
	l,data=0,""
	while(l<size):
		n = min(BLK,size-l)
		d=read_block(n)
		assert(len(d)==n)
		data += d
		l+=len(d)
	data_checksum = read_block(4)
	assert(len(data_checksum)==4)
	if(data_checksum != calc_data_checksum(data)):
		print("Error: Bad data checksum: %s != %s"%(hexlify(data_checksum),hexlify(calc_data_checksum(data))))
		exit(1)
	return cmd,flag,data

MAX_CHUNK = 0x10000
def send_recv(cmd,data="",flag_opt=3):
	idx = 0
	full = len(data)
	left = full-idx
	while True:
		lc = min(MAX_CHUNK, left)
		flags = flag_opt
		if left > MAX_CHUNK:
			flags |= 4
		print("* Write Cmd 0x%x Flags %d Data len %d"%(cmd,flags,lc))
		hdr = pack(">III",cmd,flags,lc)
		write_block(hdr + calc_hdr_checksum(hdr))
		chunk = data[idx:idx+lc]
		if chunk:
			write_block(chunk)
		write_block(calc_data_checksum(chunk))
		reply = read_packet()
		if reply[0] != cmd:
			raise ValueError("Invalid reply %d to cmd %d"%(reply[0],cmd))
		idx += lc
		left = full-idx
		if left==0:
			break
	return reply

def load_sf(p):
	f = gzip.open(p).read()
	v,_,hl = unpack(">BBI",f[:6])
	assert(v==2)
	hdr,data = f[:hl],f[hl:]
	plen, = unpack(">I", hdr[11:15])
	fs = 0
	for i in range(0,plen,0x29):
		pidx = 0xF + i
		unk,dlen,cksum_len,cksum=unpack(">IIB32s",hdr[pidx:pidx+0x29])
		assert(cksum_len == 0x20)
		assert(cksum == sha256(data[fs:fs+dlen]).digest())
		fs += dlen
	cert = hdr[15+plen:]
	cert_len, = unpack(">I",cert[:4])
	assert(len(cert)==cert_len+4)
	assert(fs==len(data))
	return (hdr, data)

def cmd_get_info():
	cmd,flag,data = send_recv(1)
	print("Device info: %s"%data)

def cmd_reboot():
	cmd,flag,data = send_recv(4)
	print("Reboot reply: %d"%cmd)

def main():
	print("Waiting device...")
	while not detect_dev():
		sleep(.5)
	print("Found device")
	try:
		cmd,flag,dev_info = read_packet(100)
		assert(cmd==1)
		print("\nDevice info: %s"%dev_info)
		print("Sending info command to kick timer")
		send_recv(1)
	except usb.core.USBError:
		print ("\tNo info received")
		cmd,flag,dev_info = send_recv(1)
		print("\tDevice info: %s"%dev_info)

	loader = load_sf("files/loader")
	boot = load_sf("files/boot")

	print ("Sending loader hdr")
	cmd,flag,reply = send_recv(5, data=loader[0])

	print ("Sending loader data")
	cmd,flag,reply = send_recv(6, data=loader[1])

	cmd,flag,dev_info = read_packet()
	assert(cmd==1)
	print("\nDevice 2 info: %s"%dev_info)

	print ("Sending 9")
	cmd,flag,reply = send_recv(9, "\x02")

	print ("Sending boot hdr")
	cmd,flag,reply = send_recv(5, data=boot[0])

	print ("Sending boot data")
	cmd,flag,reply = send_recv(6, data=boot[1])

	print ("Sending 10")
	cmd,flag,reply = send_recv(10)

	print ("Sending reboot")
	cmd,flag,reply = send_recv(4)

if __name__ == '__main__': main()
