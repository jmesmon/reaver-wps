
CONFDIR=$(HOME)/var/reaver

obj-wps    = $(addprefix wps/,wps_attr_build.o wps_attr_parse.o		\
		wps_attr_process.o wps.o wps_common.o wps_dev_attr.o	\
		wps_enrollee.o wps_registrar.o wps_ufd.o)
obj-utils  = $(addprefix utils/,base64.o common.o eloop.o ip_addr.o os_unix.o	\
		radiotap.o trace.o uuid.o wpabuf.o wpa_debug.o)

## TLS {
obj-tls += tls/asn1.o
obj-tls += tls/bignum.o
obj-tls += tls/pkcs1.o
obj-tls += tls/pkcs5.o
obj-tls += tls/pkcs8.o
obj-tls += tls/rsa.o
obj-tls += tls/tlsv1_client.o
obj-tls += tls/tlsv1_client_read.o
obj-tls += tls/tlsv1_client_write.o
obj-tls += tls/tlsv1_common.o
obj-tls += tls/tlsv1_cred.o
obj-tls += tls/tlsv1_record.o
obj-tls += tls/tlsv1_server.o
obj-tls += tls/tlsv1_server_read.o
obj-tls += tls/tlsv1_server_write.o
obj-tls += tls/x509v3.o

define DEF_CFLAGS_FOR_TLS
cflags-$1 += -DCONFIG_INTERNAL_LIBTOMMATH -DCONFIG_CRYPTO_INTERNAL

endef
$(eval $(foreach obj,$(obj-tls),$(call DEF_CFLAGS_FOR_TLS,$(obj))))
## }

## CRYPTO {

obj-crypto += crypto/aes-cbc.o
obj-crypto += crypto/aes-ctr.o
obj-crypto += crypto/aes-eax.o
obj-crypto += crypto/aes-encblock.o
obj-crypto += crypto/aes-internal.o
obj-crypto += crypto/aes-internal-dec.o
obj-crypto += crypto/aes-internal-enc.o
obj-crypto += crypto/aes-omac1.o
obj-crypto += crypto/aes-unwrap.o
obj-crypto += crypto/aes-wrap.o
obj-crypto += crypto/crypto_internal.o
obj-crypto += crypto/crypto_internal-cipher.o
obj-crypto += crypto/crypto_internal-modexp.o
obj-crypto += crypto/crypto_internal-rsa.o
obj-crypto += crypto/des-internal.o
obj-crypto += crypto/dh_group5.o
obj-crypto += crypto/dh_groups.o
obj-crypto += crypto/fips_prf_internal.o
obj-crypto += crypto/md4-internal.o
obj-crypto += crypto/md5.o
obj-crypto += crypto/md5-internal.o
obj-crypto += crypto/ms_funcs.o
obj-crypto += crypto/rc4.o
obj-crypto += crypto/sha1.o
obj-crypto += crypto/sha1-internal.o
obj-crypto += crypto/sha1-pbkdf2.o
obj-crypto += crypto/sha1-tlsprf.o
obj-crypto += crypto/sha1-tprf.o
obj-crypto += crypto/sha256.o
obj-crypto += crypto/sha256-internal.o
obj-crypto += crypto/tls_internal.o

define DEF_CFLAGS_FOR_CRYPTO
cflags-$1 += -DCONFIG_TLS_INTERNAL_CLIENT -DCONFIG_TLS_INTERNAL_SERVER

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

PCAP_LDFLAGS = -lpcap
PCAP_CFLAGS  =

LIBIW_CFLAGS =
LIBIW_LDFLAGS = -liw

ALL_CFLAGS  += -I. -Iutils -DCONF_DIR="\"$(CONFDIR)\""
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

