SRC = hello_world.c

all: hello_world_dyn hello_world_dyn_sizeopt hello_world_stat hello_world_stat_sizeopt

hello_world_dyn:
	gcc -o $@ $(SRC)

hello_world_dyn_sizeopt:
	gcc -o $@ -Os -flto -Wl,--gc-sections -s $(SRC)

hello_world_stat:
	gcc -o $@ -static $(SRC)

hello_world_stat_sizeopt:
	gcc -o $@ -static -Os -flto -Wl,--gc-sections -s $(SRC)

.PHONY: clean

clean:
	rm -rf hello_world_dyn hello_world_dyn_sizeopt hello_world_stat hello_world_stat_sizeopt

