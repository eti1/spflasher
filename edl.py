#!/usr/bin/python3
import sys
import serial
from struct import pack,unpack
from binascii import hexlify, unhexlify
import os
import time
from getopt import getopt
import gzip

def find_tty(dev_id="05c6:9008"):
	dev_id=dev_id.lower()
	BD = "/sys/bus/usb/devices/"
	for d in os.listdir(BD):
		dn = BD +"/"+d+"/"
		if os.path.isdir(dn):
			vn = dn+"idVendor"
			pn = dn+"idProduct"
			if os.path.isfile(vn) and os.path.isfile(pn):
				dev = (open(vn,'rb').read().decode().strip()+ ":" + open(pn,'rb').read().decode().strip()).lower()
				if dev == dev_id:
					for tty in os.listdir(BD + d + ":1.0/"):
						if tty.startswith("tty"):
							return "/dev/"+tty
	return None

crc_tbl = [
    0x0000, 0x1189, 0x2312, 0x329b, 0x4624, 0x57ad, 0x6536, 0x74bf,
    0x8c48, 0x9dc1, 0xaf5a, 0xbed3, 0xca6c, 0xdbe5, 0xe97e, 0xf8f7,
    0x1081, 0x0108, 0x3393, 0x221a, 0x56a5, 0x472c, 0x75b7, 0x643e,
    0x9cc9, 0x8d40, 0xbfdb, 0xae52, 0xdaed, 0xcb64, 0xf9ff, 0xe876,
    0x2102, 0x308b, 0x0210, 0x1399, 0x6726, 0x76af, 0x4434, 0x55bd,
    0xad4a, 0xbcc3, 0x8e58, 0x9fd1, 0xeb6e, 0xfae7, 0xc87c, 0xd9f5,
    0x3183, 0x200a, 0x1291, 0x0318, 0x77a7, 0x662e, 0x54b5, 0x453c,
    0xbdcb, 0xac42, 0x9ed9, 0x8f50, 0xfbef, 0xea66, 0xd8fd, 0xc974,
    0x4204, 0x538d, 0x6116, 0x709f, 0x0420, 0x15a9, 0x2732, 0x36bb,
    0xce4c, 0xdfc5, 0xed5e, 0xfcd7, 0x8868, 0x99e1, 0xab7a, 0xbaf3,
    0x5285, 0x430c, 0x7197, 0x601e, 0x14a1, 0x0528, 0x37b3, 0x263a,
    0xdecd, 0xcf44, 0xfddf, 0xec56, 0x98e9, 0x8960, 0xbbfb, 0xaa72,
    0x6306, 0x728f, 0x4014, 0x519d, 0x2522, 0x34ab, 0x0630, 0x17b9,
    0xef4e, 0xfec7, 0xcc5c, 0xddd5, 0xa96a, 0xb8e3, 0x8a78, 0x9bf1,
    0x7387, 0x620e, 0x5095, 0x411c, 0x35a3, 0x242a, 0x16b1, 0x0738,
    0xffcf, 0xee46, 0xdcdd, 0xcd54, 0xb9eb, 0xa862, 0x9af9, 0x8b70,
    0x8408, 0x9581, 0xa71a, 0xb693, 0xc22c, 0xd3a5, 0xe13e, 0xf0b7,
    0x0840, 0x19c9, 0x2b52, 0x3adb, 0x4e64, 0x5fed, 0x6d76, 0x7cff,
    0x9489, 0x8500, 0xb79b, 0xa612, 0xd2ad, 0xc324, 0xf1bf, 0xe036,
    0x18c1, 0x0948, 0x3bd3, 0x2a5a, 0x5ee5, 0x4f6c, 0x7df7, 0x6c7e,
    0xa50a, 0xb483, 0x8618, 0x9791, 0xe32e, 0xf2a7, 0xc03c, 0xd1b5,
    0x2942, 0x38cb, 0x0a50, 0x1bd9, 0x6f66, 0x7eef, 0x4c74, 0x5dfd,
    0xb58b, 0xa402, 0x9699, 0x8710, 0xf3af, 0xe226, 0xd0bd, 0xc134,
    0x39c3, 0x284a, 0x1ad1, 0x0b58, 0x7fe7, 0x6e6e, 0x5cf5, 0x4d7c,
    0xc60c, 0xd785, 0xe51e, 0xf497, 0x8028, 0x91a1, 0xa33a, 0xb2b3,
    0x4a44, 0x5bcd, 0x6956, 0x78df, 0x0c60, 0x1de9, 0x2f72, 0x3efb,
    0xd68d, 0xc704, 0xf59f, 0xe416, 0x90a9, 0x8120, 0xb3bb, 0xa232,
    0x5ac5, 0x4b4c, 0x79d7, 0x685e, 0x1ce1, 0x0d68, 0x3ff3, 0x2e7a,
    0xe70e, 0xf687, 0xc41c, 0xd595, 0xa12a, 0xb0a3, 0x8238, 0x93b1,
    0x6b46, 0x7acf, 0x4854, 0x59dd, 0x2d62, 0x3ceb, 0x0e70, 0x1ff9,
    0xf78f, 0xe606, 0xd49d, 0xc514, 0xb1ab, 0xa022, 0x92b9, 0x8330,
    0x7bc7, 0x6a4e, 0x58d5, 0x495c, 0x3de3, 0x2c6a, 0x1ef1, 0x0f78
]

def crc(buf):
	c = 0xffff
	for b in buf:
		c = ((c >> 8 ) & 0xffff ) ^ crc_tbl[( c ^ b ) & 0xff ];
	return ~c & 0xffff

def escape(buf):
	o = b""
	for c in buf:
		if c in (0x7d,0x7e):
			o += bytes((0x7d,0x20^c),)
		else:
			o += bytes((c,))
	return o

def make_frame(command):
	command += pack("<H",crc(command))
	frame = b"\x7e" + escape(command) + b"\x7e"
	return frame

def send_cmd(command):
	frame = make_frame(command)
	s.write(frame)

def read_one_char():
	to = time.time() + 5
	while time.time() < to:
		try:
			return ord(s.read(1))
		except:
			pass
	raise ValueError("Timeout while read one char")

def read_frame():
	o = b""
	c = read_one_char()
	if c != 0x7e:
		raise ValueError("invalid frame start 0x%02x"%ord(c))
	state = 0
	while True:
		c = read_one_char()
		if state == 0:
			if c == 0x7d:
				state = 1
			elif c == 0x7e:
				break
			else:
				o += bytes((c,))
		else:
			o += bytes((c^0x20,))
			state = 0
	o,(csum,) = o[:-2], unpack("<H",o[-2:])
	if csum != crc(o):
		raise ValueError(("invalid crc given=%04x != calc=%04x"%(csum,crc(o))))
	return o


def cmd_getver():
	send_cmd(b"\x0c")
	r = read_frame()
	return r[2:]

def cmd_pwroff():
	send_cmd(b"\x0e")
	r = read_frame()

def cmd_writel(addr, data):
	send_cmd(b"\x0f" + pack(">IH",addr,len(data)) + data)
	r = read_frame()
	if r != b"\x02":
		print("writel failed: %s"%hexlify(r))
		return False
	print("Written chunk at %08x, len %d"%(addr,len(data)))
	return True

def cmd_execute(addr):
	print("Executing %08x"%addr)
	send_cmd(b"\x05" + pack(">I", addr))
	print("Waiting exec reply.")
	r = read_frame()
	if r != b"\x02":
		print("exec failed: %s"%hexlify(r))
		return False
	print("Execute ok")
	return True

def upload_file(addr, data):
	N=1800
	pos = addr
	for i in range(0,len(data),N):
		chunk = data[i:i+N]
		if not cmd_writel(pos, chunk):
			print("Write failed at %08x"%pos)
			return False
		pos += len(chunk)
	return True

def main():
	global s
	mbn = gzip.open("files/exec").read()
	print("Waiting device...")
	while True:
		while True:
			tty = find_tty()
			if tty is not None:
				break
			time.sleep(.5)
		print("Device found on %s"%tty)
		try:
			s = serial.Serial(tty)
		except serial.serialutil.SerialException as e:
			print ("Exception: %s"%e)
			time.sleep(.5)
			continue
		break
	ver = cmd_getver()
	print("Version info: %s"%(ver))
	if not upload_file(0x2A000000, mbn):
		return 1
	if not cmd_execute(0x2A000000):
		return 1

if __name__ == '__main__': main()
