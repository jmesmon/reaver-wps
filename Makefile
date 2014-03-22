

obj-wps    = $(addprefix wps/,wps_attr_build.o wps_attr_parse.o wps_attr_process.o wps.o wps_common.o wps_dev_attr.o wps_enrollee.o wps_registrar.o wps_ufd.o)
obj-utils  = $(addprefix utils/,base64.o common.o eloop.o ip_addr.o os_unix.o radiotap.o trace.o uuid.o wpabuf.o wpa_debug.o)
obj-common = $(obj-wps) $(obj-utils) crypto/libcrypto.a tls/libtls.a lwe/libiw.a libwps.o argsparser.o globule.o init.o sigint.o sigalrm.o misc.o cracker.o 80211.o iface.o crc.o builder.o session.o pins.o keys.o sql.o exchange.o send.o
obj-reaver = $(obj-common) wpscrack.o
obj-wash   = $(obj-common) wpsmon.o
TARGETS = reaver wash

SQLITE3_CFLAGS  =
SQLITE3_LDFLAGS = -lsqlite3

PCAP_LDFLAGS = -lpcap
PCAP_CFLAGS  =

ALL_CFLAGS += -Ilibwps -I. -Iutils
ALL_LDFLAGS += -lm

ALL_CFLAGS  += $(PCAP_CFLAGS)  $(SQLITE3_CFLAGS)
ALL_LDFLAGS += $(PCAP_LDFLAGS) $(SQLITE3_LDFLAGS)

include base.mk

$(eval $(call sub-make,tls/libtls.a))
$(eval $(call sub-make,crypto/libcrypto.a))
$(eval $(call sub-make,lwe/libiw.a,BUILD_STATIC=yes))

# For some reason they don't clean it up...
TRASH += lwe/wireless.h


