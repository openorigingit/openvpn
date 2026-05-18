AUTOMAKE_OPTIONS = foreign

AM_TESTSUITE_SUMMARY_HEADER = ' for $(PACKAGE_STRING) Fuzz Smoke Tests'

check_PROGRAMS = ikev2_parser_fuzzer

if !CROSS_COMPILING
TESTS = $(check_PROGRAMS)
endif

ikev2_parser_fuzzer_CFLAGS = \
	-I$(top_srcdir)/include -I$(top_srcdir)/src/compat -I$(top_srcdir)/src/openvpn \
	@TEST_CFLAGS@ -DOPENVPN_FUZZ_STANDALONE
ikev2_parser_fuzzer_LDFLAGS = @TEST_LDFLAGS@
ikev2_parser_fuzzer_SOURCES = ikev2_parser_fuzzer.c \
	$(top_srcdir)/src/openvpn/provider_helper_wire.c
