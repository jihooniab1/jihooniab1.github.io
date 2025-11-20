all: BootLoader Disk.img

BootLoader:
	make -C 00.BootLoader

Disk.img: 00.BootLoader/BootLoader.bin
	cp 00.BootLoader/BootLoader.bin Disk.img

clean:
	make -C 00.BootLoader clean
	rm -f Disk.img