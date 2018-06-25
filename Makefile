DIST_DIR = $(shell pwd)/dist
OBJS_DIR = $(shell pwd)/build/obj
LIBS_DIR = $(shell pwd)/build/lib

all:
	ndk-build -C ./jni NDK_OUT=$(OBJS_DIR) NDK_LIBS_OUT=$(LIBS_DIR)

zip:
	rm -rf $(DIST_DIR)
	mkdir -p $(DIST_DIR)
	cd $(LIBS_DIR) && zip -r $(DIST_DIR)/maniacj.zip *

clean:
	-rm -rf ./build ./dist
