
CONFDIR=$(HOME)/var/reaver


## UTILS {
obj-utils += hostap/src/utils/base64.o
obj-utils += hostap/src/utils/common.o
obj-utils += hostap/src/utils/eloop.o
obj-utils += hostap/src/utils/ip_addr.o
obj-utils += hostap/src/utils/os_unix.o
obj-utils += hostap/src/utils/radiotap.o
obj-utils += hostap/src/utils/trace.o
obj-utils += hostap/src/utils/uuid.o
obj-utils += hostap/src/utils/wpabuf.o
obj-utils += hostap/src/utils/wpa_debug.o

define DEF_CFLAGS_FOR_UTILS
cflags-$1 += -Ihostap/src -Ihostap/src/utils

endef
$(eval $(foreach obj,$(obj-utils),$(call DEF_CFLAGS_FOR_UTILS,$(obj))))


## }

## WPS {
obj-wps += hostap/src/wps/wps_attr_build.o
obj-wps += hostap/src/wps/wps_attr_parse.o
obj-wps += hostap/src/wps/wps_attr_process.o
obj-wps += hostap/src/wps/wps.o
obj-wps += hostap/src/wps/wps_common.o
obj-wps += hostap/src/wps/wps_dev_attr.o
obj-wps += hostap/src/wps/wps_enrollee.o
obj-wps += hostap/src/wps/wps_registrar.o
#obj-wps += hostap/src/wps/wps_ufd.o

define DEF_CFLAGS_FOR_WPS
cflags-$1 += -Ihostap/src -Ihostap/src/utils

endef
$(eval $(foreach obj,$(obj-wps),$(call DEF_CFLAGS_FOR_WPS,$(obj))))

## }

## TLS {
obj-tls += hostap/src/tls/asn1.o
obj-tls += hostap/src/tls/bignum.o
obj-tls += hostap/src/tls/pkcs1.o
obj-tls += hostap/src/tls/pkcs5.o
obj-tls += hostap/src/tls/pkcs8.o
obj-tls += hostap/src/tls/rsa.o
obj-tls += hostap/src/tls/tlsv1_client.o
obj-tls += hostap/src/tls/tlsv1_client_read.o
obj-tls += hostap/src/tls/tlsv1_client_write.o
obj-tls += hostap/src/tls/tlsv1_common.o
obj-tls += hostap/src/tls/tlsv1_cred.o
obj-tls += hostap/src/tls/tlsv1_record.o
obj-tls += hostap/src/tls/tlsv1_server.o
obj-tls += hostap/src/tls/tlsv1_server_read.o
obj-tls += hostap/src/tls/tlsv1_server_write.o
obj-tls += hostap/src/tls/x509v3.o

define DEF_CFLAGS_FOR_TLS
cflags-$1 += -DCONFIG_INTERNAL_LIBTOMMATH -DCONFIG_CRYPTO_INTERNAL \
		-DCONFIG_TLSV1 -DCONFIG_TLSV2 \
		-Ihostap/src -Ihostap/src/utils

endef
$(eval $(foreach obj,$(obj-tls),$(call DEF_CFLAGS_FOR_TLS,$(obj))))
## }

## CRYPTO {

obj-crypto += hostap/src/crypto/aes-cbc.o
obj-crypto += hostap/src/crypto/aes-ctr.o
obj-crypto += hostap/src/crypto/aes-eax.o
obj-crypto += hostap/src/crypto/aes-encblock.o
obj-crypto += hostap/src/crypto/aes-internal.o
obj-crypto += hostap/src/crypto/aes-internal-dec.o
obj-crypto += hostap/src/crypto/aes-internal-enc.o
obj-crypto += hostap/src/crypto/aes-omac1.o
obj-crypto += hostap/src/crypto/aes-unwrap.o
obj-crypto += hostap/src/crypto/aes-wrap.o
obj-crypto += hostap/src/crypto/crypto_internal.o
obj-crypto += hostap/src/crypto/crypto_internal-cipher.o
obj-crypto += hostap/src/crypto/crypto_internal-modexp.o
obj-crypto += hostap/src/crypto/crypto_internal-rsa.o
obj-crypto += hostap/src/crypto/des-internal.o
obj-crypto += hostap/src/crypto/dh_group5.o
obj-crypto += hostap/src/crypto/dh_groups.o
obj-crypto += hostap/src/crypto/fips_prf_internal.o
obj-crypto += hostap/src/crypto/md4-internal.o
obj-crypto += hostap/src/crypto/md5.o
obj-crypto += hostap/src/crypto/md5-internal.o
obj-crypto += hostap/src/crypto/ms_funcs.o
obj-crypto += hostap/src/crypto/random.o
obj-crypto += hostap/src/crypto/rc4.o
obj-crypto += hostap/src/crypto/sha1.o
obj-crypto += hostap/src/crypto/sha1-internal.o
obj-crypto += hostap/src/crypto/sha1-pbkdf2.o
obj-crypto += hostap/src/crypto/sha1-tlsprf.o
obj-crypto += hostap/src/crypto/sha1-tprf.o
obj-crypto += hostap/src/crypto/sha256.o
obj-crypto += hostap/src/crypto/sha256-internal.o
obj-crypto += hostap/src/crypto/tls_internal.o

define DEF_CFLAGS_FOR_CRYPTO
cflags-$1 += -DCONFIG_CRYPTO_INTERNAL -DCONFIG_TLS_INTERNAL_CLIENT \
	-DCONFIG_TLS_INTERNAL_SERVER -DCONFIG_SHA256 \
	-Ihostap/src/utils -Ihostap/src

endef

$(eval $(foreach obj,$(obj-crypto),$(call DEF_CFLAGS_FOR_CRYPTO,$(obj))))
## }


## COMMON
obj-common = $(obj-tls) $(obj-wps) $(obj-utils) $(obj-crypto) \
		libwps.o argsparser.o globule.o init.o sigint.o	\
		sigalrm.o misc.o cracker.o 80211.o iface.o crc.o builder.o	\
		session.o pins.o keys.o sql.o exchange.o send.o

obj-reaver = $(obj-common) wpscrack.o
obj-wash   = $(obj-common) wpsmon.o
TARGETS_BIN = reaver wash

SQLITE3_CFLAGS  =
SQLITE3_LDFLAGS = -lsqlite3

PCAP_CFLAGS  =
PCAP_LDFLAGS = -lpcap

LIBIW_CFLAGS =
LIBIW_LDFLAGS = -liw

ALL_CFLAGS  += -DCONF_DIR="\"$(CONFDIR)\"" -Ihostap/src
ALL_LDFLAGS += -lm

ALL_CFLAGS  += $(PCAP_CFLAGS)  $(SQLITE3_CFLAGS)  $(LIBIW_CFLAGS)
ALL_LDFLAGS += $(PCAP_LDFLAGS) $(SQLITE3_LDFLAGS) $(LIBIW_LDFLAGS)

include base.mk

install: reaver.db
	mkdir -p $(CONFDIR); \
	if ! [ -e $(CONFDIR)/reaver.db ]; then \
		cp reaver.db $(CONFDIR)/reaver.db; \
	fi

# For some reason they don't clean it up...
TRASH += lwe/wireless.h

