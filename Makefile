NAME=kvm-inspect
KDIR=../linux/
REMOTE=root@ubuntu-vm
SOURCES=main.c utils.c

obj-m := $(NAME).o
ccflags-y := -std=gnu99 -Wno-declaration-after-statement -Og -DMODULE_NAME="\"$(NAME)\""
$(NAME)-y := $(SOURCES:.c=.o)
TARGET=build/$(NAME).ko
BUILD_FILES := $(SOURCES:.c=.o) $(NAME).o $(NAME).ko .*.cmd *.mod *.mod.? modules.order Module.symvers
.PHONY: run build clean reset upload remove start stop debug

run: $(TARGET) remove upload start

build: $(TARGET)

$(TARGET): $(SOURCES)
	@echo moving build files to current directory
	@cd build && mv $(BUILD_FILES) ../ >/dev/null 2>&1 || echo -n
	make -C $(KDIR) M=$(PWD)
	@echo moving build files back to build directory
	@mv $(BUILD_FILES) build >/dev/null 2>&1 || echo -n

clean:
	rm -rf build/* build/.??*
	rm -f $(BUILD_FILES)

reset:
	virsh snapshot-revert ubuntu debug
	ssh $(REMOTE) virsh snapshot-revert tiny base

upload:
	scp $(TARGET) $(REMOTE):

remove:
	-ssh $(REMOTE) rmmod $(NAME)

start:
	ssh $(REMOTE) dmesg -C
	-ssh $(REMOTE) insmod $(NAME).ko
	ssh -t $(REMOTE) dmesg -w

stop:
	ssh $(REMOTE) dmesg -C
	-ssh $(REMOTE) rmmod $(NAME).ko
	ssh -t $(REMOTE) dmesg -c

debug:
	gdb $(KDIR)/vmlinux -ex 'target remote :1234'
