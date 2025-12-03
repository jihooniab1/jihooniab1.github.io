all: BootLoader Kernel32 Disk.img

BootLoader:
	make -C 00.BootLoader

Kernel32:
	make -C 01.Kernel32

Disk.img: 00.BootLoader/BootLoader.bin 01.Kernel32/VirtualOS.bin
	cat 00.BootLoader/BootLoader.bin 01.Kernel32/VirtualOS.bin > Disk.img

clean:
	make -C 00.BootLoader clean
	make -C 01.Kernel32 clean
	rm -f Disk.img