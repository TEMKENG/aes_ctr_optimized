SRC = hello_world.cpp

all: hello_world_dyn hello_world_dyn_sizeopt hello_world_stat hello_world_stat_sizeopt

hello_world_dyn:
	g++ -o $@ $(SRC)

hello_world_dyn_sizeopt:
	g++ -o $@ -Os -flto -Wl,--gc-sections -s $(SRC)

hello_world_stat:
	g++ -o $@ -static -static-libstdc++ $(SRC)

hello_world_stat_sizeopt:
	g++ -o $@ -static -static-libstdc++ -Os -flto -Wl,--gc-sections -s $(SRC)

.PHONY: clean

clean:
	rm -rf hello_world_dyn hello_world_dyn_sizeopt hello_world_stat hello_world_stat_sizeopt

