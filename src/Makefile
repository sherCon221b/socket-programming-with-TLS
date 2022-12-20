CC=gcc
LIB_NAME = socket_api
TARGET_SERVER = server
TARGET_CLIENT = client

INC_CURR_DIR = ../include
LIB_CURR_DIR = ../lib
CFLAGS = -g -Wall
INCLUDES = -I$(INC_CURR_DIR) -I/root/SimOpenssl/prefix/include
LIBRARIES = -L/root/SimOpenssl/prefix/lib
BUILD_DIR = ../build
INSTALL = install
EXPORTED_LIB_DIR = /usr/lib

LIBS= -lpthread -lsocket_api -lssl -lcrypto

_DEPS = socket_api.h
DEPS = $(patsubst %,$(INC_CURR_DIR)/%,$(_DEPS))

EXPLIB_TARGETS = lib$(LIB_NAME).so
LIB_NAME_OBJS = $(BUILD_DIR)/$(LIB_NAME).o

all: lib $(TARGET_SERVER) $(TARGET_CLIENT)

lib: $(LIB_CURR_DIR)/$(EXPLIB_TARGETS)

$(LIB_CURR_DIR)/$(EXPLIB_TARGETS): $(LIB_NAME_OBJS)
	@$(RM) $@*
	$(CC) -shared -o $@ $<

$(LIB_NAME_OBJS): $(LIB_NAME).c $(DEPS)
	@([ -d $(LIB_CURR_DIR) ] || mkdir -p $(LIB_CURR_DIR))
	@([ -d $(BUILD_DIR) ] || mkdir -p $(BUILD_DIR))
	$(CC) -c -fPIC -o $@ $< $(CFLAGS) $(INCLUDES)

$(TARGET_SERVER): $(TARGET_SERVER).c
	$(CC) -o $@ $< $(CFLAGS) $(INCLUDES) $(LIBRARIES) ${LIBS}

$(TARGET_CLIENT): $(TARGET_CLIENT).c
	$(CC) -o $@ $< $(CFLAGS) $(INCLUDES) $(LIBRARIES) ${LIBS}

install:
	$(INSTALL) -d $(BUILD_DIR)
	$(INSTALL) -c -m 445 $(LIB_CURR_DIR)/$(EXPLIB_TARGETS) $(EXPORTED_LIB_DIR)

uninstall:
	@(cd $(EXPORTED_LIB_DIR) && \
	$(RM) $(EXPLIB_TARGETS) )

.PHONY: clean

clean:	
	$(RM) -r $(BUILD_DIR) $(LIB_CURR_DIR) $(TARGET_SERVER) $(TARGET_CLIENT)