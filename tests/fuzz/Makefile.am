AUTOMAKE_OPTIONS = foreign

AM_TESTSUITE_SUMMARY_HEADER = ' for $(PACKAGE_STRING) Fuzz Smoke Tests'

check_PROGRAMS = ikev2_parser_fuzzer provider_helper_ipc_fuzzer \
	eap_tls_payload_fuzzer x509_metadata_fuzzer

if !CROSS_COMPILING
TESTS = $(check_PROGRAMS)
endif

ikev2_parser_fuzzer_CFLAGS = \
	-I$(top_srcdir)/include -I$(top_srcdir)/src/compat -I$(top_srcdir)/src/openvpn \
	@TEST_CFLAGS@ -DOPENVPN_FUZZ_STANDALONE
ikev2_parser_fuzzer_LDFLAGS = @TEST_LDFLAGS@
ikev2_parser_fuzzer_SOURCES = ikev2_parser_fuzzer.c \
	$(top_srcdir)/src/openvpn/provider_helper_wire.c

provider_helper_ipc_fuzzer_CFLAGS = \
	-I$(top_srcdir)/include -I$(top_srcdir)/src/compat -I$(top_srcdir)/src/openvpn \
	@TEST_CFLAGS@ -DOPENVPN_FUZZ_STANDALONE
provider_helper_ipc_fuzzer_LDFLAGS = @TEST_LDFLAGS@
provider_helper_ipc_fuzzer_SOURCES = provider_helper_ipc_fuzzer.c \
	$(top_srcdir)/src/openvpn/provider_helper_wire.c

eap_tls_payload_fuzzer_CFLAGS = \
	-I$(top_srcdir)/include -I$(top_srcdir)/src/compat -I$(top_srcdir)/src/openvpn \
	@TEST_CFLAGS@ -DOPENVPN_FUZZ_STANDALONE
eap_tls_payload_fuzzer_LDFLAGS = @TEST_LDFLAGS@
eap_tls_payload_fuzzer_SOURCES = eap_tls_payload_fuzzer.c \
	$(top_srcdir)/src/openvpn/provider_helper_wire.c

x509_metadata_fuzzer_CFLAGS = \
	-I$(top_srcdir)/include -I$(top_srcdir)/src/compat -I$(top_srcdir)/src/openvpn \
	@TEST_CFLAGS@ -DOPENVPN_FUZZ_STANDALONE -Wno-unused-function
x509_metadata_fuzzer_LDFLAGS = @TEST_LDFLAGS@
x509_metadata_fuzzer_LDADD = \
	$(top_builddir)/src/compat/libcompat.la \
	$(OPTIONAL_CRYPTO_LIBS) \
	$(SOCKETS_LIBS)
x509_metadata_fuzzer_SOURCES = x509_metadata_fuzzer.c \
	$(top_srcdir)/src/openvpn/openvpn_ikev2_helper.c \
	$(top_srcdir)/src/openvpn/provider_client_auth.c \
	$(top_srcdir)/src/openvpn/provider_helper_wire.c \
	$(top_srcdir)/src/openvpn/provider_xfrm.c \
	$(top_srcdir)/src/openvpn/provider_xfrm_linux.c
