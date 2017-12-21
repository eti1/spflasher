all: flash-boot

edl:
	./edl.py

flash-boot: edl
	./loader.py
