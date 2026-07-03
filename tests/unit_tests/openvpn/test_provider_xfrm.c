/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2026 OpenVPN Inc <sales@openvpn.net>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2
 *  as published by the Free Software Foundation.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "syshead.h"

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include "provider_xfrm.h"
#include "provider_xfrm_linux.h"
#include "test_common.h"

#if defined(TARGET_LINUX)
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/xfrm.h>
#include <sched.h>
#include <sys/wait.h>

#ifndef UDP_ENCAP_ESPINUDP
#define UDP_ENCAP_ESPINUDP 2
#endif
#endif

static const char *default_local_ts[] = {
    "10.88.0.1/32[tcp/443]",
};

static const char *default_remote_ts[] = {
    "10.88.0.2/32",
};

static const uint8_t default_i2r_key[PROVIDER_XFRM_KEYMAT_MAX_BYTES] = {
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21,
    0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a,
    0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33,
};

static const uint8_t default_r2i_key[PROVIDER_XFRM_KEYMAT_MAX_BYTES] = {
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
    0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51,
    0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a,
    0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x60, 0x61, 0x62, 0x63,
};

static struct provider_xfrm_lease_spec
default_lease_spec(void)
{
    return (struct provider_xfrm_lease_spec) {
        .lease_id = 17,
        .provider_session_id = 7,
        .policy_revision = 3,
        .principal = "alice@example.test",
        .local_outer_address = "198.51.100.10",
        .remote_outer_address = "203.0.113.20",
        .assigned_inner_address = "10.88.0.2",
        .allowed_local_ts = default_local_ts,
        .local_ts_count = SIZE(default_local_ts),
        .allowed_remote_ts = default_remote_ts,
        .remote_ts_count = SIZE(default_remote_ts),
        .mark_value = 0x4200,
        .mark_mask = 0xffff,
        .if_id = 12,
        .reqid = 1100,
        .nftables_chain_name = "openvpn_ikev2_17",
        .expires = 2000,
        .rekey_deadline = 1900,
    };
}

static struct provider_xfrm_child_sa_spec
default_child_sa_spec(void)
{
    return (struct provider_xfrm_child_sa_spec) {
        .lease_id = 17,
        .provider_session_id = 7,
        .policy_revision = 3,
        .mark_value = 0x4200,
        .mark_mask = 0xffff,
        .if_id = 12,
        .reqid = 1100,
        .local_outer_ipv4 = 0xc633640a,
        .remote_outer_ipv4 = 0xcb007114,
        .local_outer_port = 4500,
        .remote_outer_port = 53124,
        .local_ts = {
            .start_addr = 0x0a580001,
            .end_addr = 0x0a580001,
            .start_port = 443,
            .end_port = 443,
            .ip_protocol_id = IPPROTO_TCP,
        },
        .remote_ts = {
            .start_addr = 0x0a580002,
            .end_addr = 0x0a580002,
            .start_port = 10000,
            .end_port = 10000,
            .ip_protocol_id = IPPROTO_TCP,
        },
        .initiator_inbound_spi = 0x01020304,
        .responder_inbound_spi = 0xaabbccdd,
        .cipher = PROVIDER_XFRM_CIPHER_AES_GCM_16,
        .key_bits = 256,
        .initiator_to_responder_key = default_i2r_key,
        .initiator_to_responder_key_len = sizeof(default_i2r_key),
        .responder_to_initiator_key = default_r2i_key,
        .responder_to_initiator_key_len = sizeof(default_r2i_key),
    };
}

static struct provider_xfrm_child_sa_spec
alternate_child_sa_spec(void)
{
    struct provider_xfrm_child_sa_spec spec = default_child_sa_spec();
    spec.lease_id = 18;
    spec.provider_session_id = 8;
    spec.policy_revision = 4;
    spec.mark_value = 0x4300;
    spec.if_id = 13;
    spec.reqid = 1101;
    spec.remote_outer_ipv4 = 0xcb007115;
    spec.local_ts.start_addr = 0x0a580003;
    spec.local_ts.end_addr = 0x0a580003;
    spec.remote_ts.start_addr = 0x0a580004;
    spec.remote_ts.end_addr = 0x0a580004;
    spec.initiator_inbound_spi = 0x01020305;
    spec.responder_inbound_spi = 0xaabbccde;
    return spec;
}

static struct provider_xfrm_lease
build_default_lease(void)
{
    struct provider_xfrm_lease lease;
    struct provider_xfrm_result result;
    struct provider_xfrm_lease_spec spec = default_lease_spec();

    assert_true(provider_xfrm_lease_build(&lease, &spec, &result));
    assert_true(result.ok);
    return lease;
}

static void
test_provider_xfrm_builds_lease(void **state)
{
    (void)state;

    struct provider_xfrm_lease lease = build_default_lease();

    assert_int_equal(lease.lease_id, 17);
    assert_int_equal(lease.provider_session_id, 7);
    assert_int_equal(lease.policy_revision, 3);
    assert_string_equal(lease.principal, "alice@example.test");
    assert_string_equal(lease.local_outer_address, "198.51.100.10");
    assert_string_equal(lease.remote_outer_address, "203.0.113.20");
    assert_string_equal(lease.assigned_inner_address, "10.88.0.2");
    assert_int_equal(lease.local_ts_count, 1);
    assert_string_equal(lease.allowed_local_ts[0], "10.88.0.1/32[tcp/443]");
    assert_int_equal(lease.remote_ts_count, 1);
    assert_string_equal(lease.allowed_remote_ts[0], "10.88.0.2/32");
    assert_int_equal(lease.mark_value, 0x4200);
    assert_int_equal(lease.mark_mask, 0xffff);
    assert_int_equal(lease.if_id, 12);
    assert_int_equal(lease.reqid, 1100);
    assert_string_equal(lease.nftables_chain_name, "openvpn_ikev2_17");
}

static void
test_provider_xfrm_rejects_missing_required_fields(void **state)
{
    (void)state;

    struct provider_xfrm_lease lease;
    struct provider_xfrm_result result;
    struct provider_xfrm_lease_spec spec = default_lease_spec();

    spec.reqid = 0;
    assert_false(provider_xfrm_lease_build(&lease, &spec, &result));
    assert_false(result.ok);
    assert_non_null(strstr(result.reason, "reqid"));

    spec = default_lease_spec();
    spec.principal = NULL;
    assert_false(provider_xfrm_lease_build(&lease, &spec, &result));
    assert_false(result.ok);
    assert_non_null(strstr(result.reason, "principal"));
}

static void
test_provider_xfrm_rejects_too_many_selectors(void **state)
{
    (void)state;

    const char *selectors[PROVIDER_XFRM_MAX_SELECTORS + 1];
    for (size_t i = 0; i < SIZE(selectors); ++i)
    {
        selectors[i] = "10.88.0.1/32";
    }

    struct provider_xfrm_lease lease;
    struct provider_xfrm_result result;
    struct provider_xfrm_lease_spec spec = default_lease_spec();
    spec.allowed_local_ts = selectors;
    spec.local_ts_count = SIZE(selectors);

    assert_false(provider_xfrm_lease_build(&lease, &spec, &result));
    assert_false(result.ok);
    assert_non_null(strstr(result.reason, "too many"));
}

static void
test_provider_xfrm_authorizes_only_exact_selectors(void **state)
{
    (void)state;

    struct provider_xfrm_lease lease = build_default_lease();
    struct provider_xfrm_result result;

    assert_true(provider_xfrm_lease_allows_child_sa(
        &lease, "10.88.0.1/32[tcp/443]", "10.88.0.2/32", 3, &result));
    assert_true(result.ok);

    assert_false(provider_xfrm_lease_allows_child_sa(
        &lease, "10.88.0.1/32[tcp/443]", "10.88.0.0/24", 3, &result));
    assert_false(result.ok);
    assert_non_null(strstr(result.reason, "selectors"));

    assert_false(provider_xfrm_lease_allows_child_sa(
        &lease, "10.88.0.1/32[tcp/443]", "10.88.0.2/32", 4, &result));
    assert_false(result.ok);
    assert_non_null(strstr(result.reason, "stale policy"));
}

static void
test_provider_xfrm_cleanup_predicate_matches_only_owned_state(void **state)
{
    (void)state;

    struct provider_xfrm_lease lease = build_default_lease();
    struct provider_xfrm_result result;

    assert_true(provider_xfrm_lease_add_spi_tuple(
        &lease, 0x10000001, 0x20000001, &result));
    assert_true(result.ok);

    struct provider_xfrm_state_identity state_id = {
        .lease_id = lease.lease_id,
        .reqid = lease.reqid,
        .mark_value = lease.mark_value,
        .mark_mask = lease.mark_mask,
        .if_id = lease.if_id,
        .local_outer_address = lease.local_outer_address,
        .remote_outer_address = lease.remote_outer_address,
        .spi = 0x10000001,
    };

    assert_true(provider_xfrm_state_matches_lease(&lease, &state_id));

    state_id.reqid = 9999;
    assert_false(provider_xfrm_state_matches_lease(&lease, &state_id));
    state_id.reqid = lease.reqid;

    state_id.mark_mask = 0xff00;
    assert_false(provider_xfrm_state_matches_lease(&lease, &state_id));
    state_id.mark_mask = lease.mark_mask;

    state_id.remote_outer_address = "203.0.113.99";
    assert_false(provider_xfrm_state_matches_lease(&lease, &state_id));
    state_id.remote_outer_address = lease.remote_outer_address;

    state_id.spi = 0x30000001;
    assert_false(provider_xfrm_state_matches_lease(&lease, &state_id));
}

static void
test_provider_xfrm_rejects_empty_spi_tuple(void **state)
{
    (void)state;

    struct provider_xfrm_lease lease = build_default_lease();
    struct provider_xfrm_result result;

    assert_false(provider_xfrm_lease_add_spi_tuple(&lease, 0, 0x20000001, &result));
    assert_false(result.ok);
    assert_non_null(strstr(result.reason, "SPI"));
}

static void
test_provider_xfrm_builds_child_sa_plan(void **state)
{
    (void)state;

    struct provider_xfrm_child_sa_plan plan;
    struct provider_xfrm_result result;
    struct provider_xfrm_child_sa_spec spec = default_child_sa_spec();

    assert_true(provider_xfrm_child_sa_plan_build(&plan, &spec, &result));
    assert_true(result.ok);

    assert_int_equal(plan.lease_id, spec.lease_id);
    assert_int_equal(plan.provider_session_id, spec.provider_session_id);
    assert_int_equal(plan.policy_revision, spec.policy_revision);

    assert_int_equal(plan.inbound.direction, PROVIDER_XFRM_DIRECTION_IN);
    assert_int_equal(plan.inbound.src_outer_ipv4, spec.remote_outer_ipv4);
    assert_int_equal(plan.inbound.dst_outer_ipv4, spec.local_outer_ipv4);
    assert_int_equal(plan.inbound.src_outer_port, spec.remote_outer_port);
    assert_int_equal(plan.inbound.dst_outer_port, spec.local_outer_port);
    assert_memory_equal(&plan.inbound.src_ts, &spec.remote_ts,
                        sizeof(plan.inbound.src_ts));
    assert_memory_equal(&plan.inbound.dst_ts, &spec.local_ts,
                        sizeof(plan.inbound.dst_ts));
    assert_int_equal(plan.inbound.spi, spec.responder_inbound_spi);
    assert_int_equal(plan.inbound.reqid, spec.reqid);
    assert_int_equal(plan.inbound.mark_value, spec.mark_value);
    assert_int_equal(plan.inbound.mark_mask, spec.mark_mask);
    assert_int_equal(plan.inbound.if_id, spec.if_id);
    assert_int_equal(plan.inbound.cipher, spec.cipher);
    assert_int_equal(plan.inbound.key_bits, spec.key_bits);
    assert_int_equal(plan.inbound.key_len, sizeof(default_i2r_key));
    assert_memory_equal(plan.inbound.key, default_i2r_key,
                        sizeof(default_i2r_key));

    assert_int_equal(plan.outbound.direction, PROVIDER_XFRM_DIRECTION_OUT);
    assert_int_equal(plan.outbound.src_outer_ipv4, spec.local_outer_ipv4);
    assert_int_equal(plan.outbound.dst_outer_ipv4, spec.remote_outer_ipv4);
    assert_int_equal(plan.outbound.src_outer_port, spec.local_outer_port);
    assert_int_equal(plan.outbound.dst_outer_port, spec.remote_outer_port);
    assert_memory_equal(&plan.outbound.src_ts, &spec.local_ts,
                        sizeof(plan.outbound.src_ts));
    assert_memory_equal(&plan.outbound.dst_ts, &spec.remote_ts,
                        sizeof(plan.outbound.dst_ts));
    assert_int_equal(plan.outbound.spi, spec.initiator_inbound_spi);
    assert_int_equal(plan.outbound.reqid, spec.reqid);
    assert_int_equal(plan.outbound.mark_value, spec.mark_value);
    assert_int_equal(plan.outbound.mark_mask, spec.mark_mask);
    assert_int_equal(plan.outbound.if_id, spec.if_id);
    assert_int_equal(plan.outbound.cipher, spec.cipher);
    assert_int_equal(plan.outbound.key_bits, spec.key_bits);
    assert_int_equal(plan.outbound.key_len, sizeof(default_r2i_key));
    assert_memory_equal(plan.outbound.key, default_r2i_key,
                        sizeof(default_r2i_key));

    const uint8_t zero_key[PROVIDER_XFRM_KEYMAT_MAX_BYTES] = { 0 };
    provider_xfrm_child_sa_plan_clear(&plan);
    assert_int_equal(plan.lease_id, 0);
    assert_int_equal(plan.inbound.key_len, 0);
    assert_memory_equal(plan.inbound.key, zero_key, sizeof(zero_key));
    assert_memory_equal(plan.outbound.key, zero_key, sizeof(zero_key));
}

static void
test_provider_xfrm_rejects_invalid_child_sa_plan(void **state)
{
    (void)state;

    struct provider_xfrm_child_sa_plan plan;
    struct provider_xfrm_result result;
    struct provider_xfrm_child_sa_spec spec = default_child_sa_spec();

    spec.responder_inbound_spi = 0;
    assert_false(provider_xfrm_child_sa_plan_build(&plan, &spec, &result));
    assert_false(result.ok);
    assert_non_null(strstr(result.reason, "SPI"));

    spec = default_child_sa_spec();
    spec.initiator_inbound_spi = spec.responder_inbound_spi;
    assert_false(provider_xfrm_child_sa_plan_build(&plan, &spec, &result));
    assert_false(result.ok);
    assert_non_null(strstr(result.reason, "distinct"));

    spec = default_child_sa_spec();
    spec.remote_outer_port = 0;
    assert_false(provider_xfrm_child_sa_plan_build(&plan, &spec, &result));
    assert_false(result.ok);
    assert_non_null(strstr(result.reason, "UDP ports"));

    spec = default_child_sa_spec();
    spec.initiator_to_responder_key_len = sizeof(default_i2r_key) - 1;
    assert_false(provider_xfrm_child_sa_plan_build(&plan, &spec, &result));
    assert_false(result.ok);
    assert_non_null(strstr(result.reason, "key material"));

    spec = default_child_sa_spec();
    spec.local_ts.start_addr = spec.local_ts.end_addr + 1;
    assert_false(provider_xfrm_child_sa_plan_build(&plan, &spec, &result));
    assert_false(result.ok);
    assert_non_null(strstr(result.reason, "selector"));
}

#if defined(TARGET_LINUX)
static const struct rtattr *
test_provider_xfrm_linux_find_attr(
    const struct provider_xfrm_linux_message *message,
    size_t payload_len,
    unsigned short type)
{
    const struct nlmsghdr *nlh = (const struct nlmsghdr *)message->data;
    const size_t attr_offset = NLMSG_ALIGN(NLMSG_LENGTH(payload_len));
    int attr_len = (int)(nlh->nlmsg_len - attr_offset);
    const struct rtattr *rta =
        (const struct rtattr *)(message->data + attr_offset);
    for (; RTA_OK(rta, attr_len); rta = RTA_NEXT(rta, attr_len))
    {
        if (rta->rta_type == type)
        {
            return rta;
        }
    }
    return NULL;
}
#endif

static void
test_provider_xfrm_linux_builds_child_sa_messages(void **state)
{
    (void)state;
#if !defined(TARGET_LINUX)
    skip();
#else
    struct provider_xfrm_child_sa_plan plan;
    struct provider_xfrm_result result;
    struct provider_xfrm_child_sa_spec spec = default_child_sa_spec();

    assert_true(provider_xfrm_child_sa_plan_build(&plan, &spec, &result));
    assert_true(result.ok);

    struct provider_xfrm_linux_message_plan messages;
    assert_true(provider_xfrm_linux_child_sa_messages_build(&messages, &plan,
                                                            &result));
    assert_true(result.ok);
    assert_int_equal(messages.count, 5);

    const struct nlmsghdr *in_sa_nlh =
        (const struct nlmsghdr *)messages.messages[0].data;
    assert_int_equal(in_sa_nlh->nlmsg_type, XFRM_MSG_NEWSA);
    assert_true(in_sa_nlh->nlmsg_flags & NLM_F_REQUEST);
    const struct xfrm_usersa_info *in_sa = NLMSG_DATA(in_sa_nlh);
    assert_int_equal(in_sa->family, AF_INET);
    assert_int_equal(in_sa->mode, XFRM_MODE_TUNNEL);
    assert_int_equal(in_sa->id.proto, IPPROTO_ESP);
    assert_int_equal(ntohl(in_sa->id.spi), spec.responder_inbound_spi);
    assert_int_equal(ntohl(in_sa->id.daddr.a4), spec.local_outer_ipv4);
    assert_int_equal(ntohl(in_sa->saddr.a4), spec.remote_outer_ipv4);
    assert_int_equal(in_sa->reqid, spec.reqid);
    assert_int_equal(in_sa->replay_window, 0);

    const struct rtattr *replay_attr = test_provider_xfrm_linux_find_attr(
        &messages.messages[0], sizeof(*in_sa), XFRMA_REPLAY_ESN_VAL);
    assert_non_null(replay_attr);
    const struct xfrm_replay_state_esn *replay = RTA_DATA(replay_attr);
    assert_int_equal(replay->bmp_len, 32);
    assert_int_equal(replay->replay_window, 1024);

    const struct rtattr *aead_attr = test_provider_xfrm_linux_find_attr(
        &messages.messages[0], sizeof(*in_sa), XFRMA_ALG_AEAD);
    assert_non_null(aead_attr);
    const struct xfrm_algo_aead *aead = RTA_DATA(aead_attr);
    assert_string_equal(aead->alg_name, "rfc4106(gcm(aes))");
    assert_int_equal(aead->alg_key_len, sizeof(default_i2r_key) * 8);
    assert_int_equal(aead->alg_icv_len, 128);
    assert_memory_equal(aead->alg_key, default_i2r_key,
                        sizeof(default_i2r_key));

    const struct rtattr *encap_attr = test_provider_xfrm_linux_find_attr(
        &messages.messages[0], sizeof(*in_sa), XFRMA_ENCAP);
    assert_non_null(encap_attr);
    const struct xfrm_encap_tmpl *encap = RTA_DATA(encap_attr);
    assert_int_equal(encap->encap_type, UDP_ENCAP_ESPINUDP);
    assert_int_equal(ntohs(encap->encap_sport), spec.remote_outer_port);
    assert_int_equal(ntohs(encap->encap_dport), spec.local_outer_port);

    const struct rtattr *mark_attr = test_provider_xfrm_linux_find_attr(
        &messages.messages[0], sizeof(*in_sa), XFRMA_MARK);
    assert_non_null(mark_attr);
    const struct xfrm_mark *mark = RTA_DATA(mark_attr);
    assert_int_equal(mark->v, spec.mark_value);
    assert_int_equal(mark->m, spec.mark_mask);

    const struct nlmsghdr *out_sa_nlh =
        (const struct nlmsghdr *)messages.messages[1].data;
    assert_int_equal(out_sa_nlh->nlmsg_type, XFRM_MSG_NEWSA);
    const struct xfrm_usersa_info *out_sa = NLMSG_DATA(out_sa_nlh);
    assert_int_equal(ntohl(out_sa->id.spi), spec.initiator_inbound_spi);
    assert_int_equal(ntohl(out_sa->id.daddr.a4), spec.remote_outer_ipv4);
    assert_int_equal(ntohl(out_sa->saddr.a4), spec.local_outer_ipv4);
    assert_int_equal(out_sa->replay_window, 0);
    assert_null(test_provider_xfrm_linux_find_attr(
                    &messages.messages[1], sizeof(*out_sa),
                    XFRMA_REPLAY_ESN_VAL));

    const struct nlmsghdr *in_pol_nlh =
        (const struct nlmsghdr *)messages.messages[2].data;
    const struct nlmsghdr *fwd_pol_nlh =
        (const struct nlmsghdr *)messages.messages[3].data;
    const struct nlmsghdr *out_pol_nlh =
        (const struct nlmsghdr *)messages.messages[4].data;
    assert_int_equal(in_pol_nlh->nlmsg_type, XFRM_MSG_NEWPOLICY);
    assert_int_equal(fwd_pol_nlh->nlmsg_type, XFRM_MSG_NEWPOLICY);
    assert_int_equal(out_pol_nlh->nlmsg_type, XFRM_MSG_NEWPOLICY);
    const struct xfrm_userpolicy_info *in_pol = NLMSG_DATA(in_pol_nlh);
    const struct xfrm_userpolicy_info *fwd_pol = NLMSG_DATA(fwd_pol_nlh);
    const struct xfrm_userpolicy_info *out_pol = NLMSG_DATA(out_pol_nlh);
    assert_int_equal(in_pol->dir, XFRM_POLICY_IN);
    assert_int_equal(fwd_pol->dir, XFRM_POLICY_FWD);
    assert_int_equal(out_pol->dir, XFRM_POLICY_OUT);
    assert_int_equal(in_pol->share, XFRM_SHARE_ANY);
    assert_int_equal(fwd_pol->share, XFRM_SHARE_ANY);
    assert_int_equal(out_pol->share, XFRM_SHARE_ANY);

    const struct rtattr *in_tmpl_attr = test_provider_xfrm_linux_find_attr(
        &messages.messages[2], sizeof(*in_pol), XFRMA_TMPL);
    assert_non_null(in_tmpl_attr);
    const struct xfrm_user_tmpl *in_tmpl = RTA_DATA(in_tmpl_attr);
    assert_int_equal(in_tmpl->id.spi, 0);
    assert_int_equal(in_tmpl->reqid, spec.reqid);
    assert_int_equal(in_tmpl->share, XFRM_SHARE_ANY);
    assert_int_equal(in_tmpl->aalgos, 0xffffffffu);
    assert_int_equal(in_tmpl->ealgos, 0xffffffffu);
    assert_int_equal(in_tmpl->calgos, 0xffffffffu);

    const struct rtattr *out_tmpl_attr = test_provider_xfrm_linux_find_attr(
        &messages.messages[4], sizeof(*out_pol), XFRMA_TMPL);
    assert_non_null(out_tmpl_attr);
    const struct xfrm_user_tmpl *out_tmpl = RTA_DATA(out_tmpl_attr);
    assert_int_equal(out_tmpl->id.spi, 0);
    assert_int_equal(out_tmpl->reqid, spec.reqid);
    assert_int_equal(out_tmpl->share, XFRM_SHARE_ANY);
    assert_int_equal(out_tmpl->aalgos, 0xffffffffu);
    assert_int_equal(out_tmpl->ealgos, 0xffffffffu);
    assert_int_equal(out_tmpl->calgos, 0xffffffffu);

    provider_xfrm_linux_message_plan_clear(&messages);
    provider_xfrm_child_sa_plan_clear(&plan);
#endif
}

static void
test_provider_xfrm_linux_rejects_unrepresentable_selectors(void **state)
{
    (void)state;
#if !defined(TARGET_LINUX)
    skip();
#else
    struct provider_xfrm_child_sa_plan plan;
    struct provider_xfrm_linux_message_plan messages;
    struct provider_xfrm_result result;
    struct provider_xfrm_child_sa_spec spec = default_child_sa_spec();

    spec.local_ts.end_addr = spec.local_ts.start_addr + 2;
    assert_true(provider_xfrm_child_sa_plan_build(&plan, &spec, &result));
    assert_false(provider_xfrm_linux_child_sa_messages_build(&messages, &plan,
                                                             &result));
    assert_false(result.ok);
    assert_non_null(strstr(result.reason, "CIDR-compatible"));
    provider_xfrm_child_sa_plan_clear(&plan);

    spec = default_child_sa_spec();
    spec.remote_ts.end_port = spec.remote_ts.start_port + 10;
    assert_true(provider_xfrm_child_sa_plan_build(&plan, &spec, &result));
    assert_false(provider_xfrm_linux_child_sa_messages_build(&messages, &plan,
                                                             &result));
    assert_false(result.ok);
    assert_non_null(strstr(result.reason, "port selectors"));
    provider_xfrm_child_sa_plan_clear(&plan);
#endif
}

static void
test_provider_xfrm_linux_builds_child_sa_delete_messages(void **state)
{
    (void)state;
#if !defined(TARGET_LINUX)
    skip();
#else
    struct provider_xfrm_child_sa_plan plan;
    struct provider_xfrm_linux_message_plan messages;
    struct provider_xfrm_result result;
    struct provider_xfrm_child_sa_spec spec = default_child_sa_spec();

    assert_true(provider_xfrm_child_sa_plan_build(&plan, &spec, &result));
    assert_true(provider_xfrm_linux_child_sa_delete_messages_build(
                    &messages, &plan, &result));
    assert_true(result.ok);
    assert_int_equal(messages.count, 5);

    const struct nlmsghdr *in_pol_nlh =
        (const struct nlmsghdr *)messages.messages[0].data;
    const struct nlmsghdr *fwd_pol_nlh =
        (const struct nlmsghdr *)messages.messages[1].data;
    const struct nlmsghdr *out_pol_nlh =
        (const struct nlmsghdr *)messages.messages[2].data;
    assert_int_equal(in_pol_nlh->nlmsg_type, XFRM_MSG_DELPOLICY);
    assert_int_equal(fwd_pol_nlh->nlmsg_type, XFRM_MSG_DELPOLICY);
    assert_int_equal(out_pol_nlh->nlmsg_type, XFRM_MSG_DELPOLICY);
    const struct xfrm_userpolicy_id *in_pol = NLMSG_DATA(in_pol_nlh);
    const struct xfrm_userpolicy_id *fwd_pol = NLMSG_DATA(fwd_pol_nlh);
    const struct xfrm_userpolicy_id *out_pol = NLMSG_DATA(out_pol_nlh);
    assert_int_equal(in_pol->dir, XFRM_POLICY_IN);
    assert_int_equal(fwd_pol->dir, XFRM_POLICY_FWD);
    assert_int_equal(out_pol->dir, XFRM_POLICY_OUT);

    const struct nlmsghdr *in_sa_nlh =
        (const struct nlmsghdr *)messages.messages[3].data;
    const struct nlmsghdr *out_sa_nlh =
        (const struct nlmsghdr *)messages.messages[4].data;
    assert_int_equal(in_sa_nlh->nlmsg_type, XFRM_MSG_DELSA);
    assert_int_equal(out_sa_nlh->nlmsg_type, XFRM_MSG_DELSA);
    const struct xfrm_usersa_id *in_sa = NLMSG_DATA(in_sa_nlh);
    const struct xfrm_usersa_id *out_sa = NLMSG_DATA(out_sa_nlh);
    assert_int_equal(ntohl(in_sa->spi), spec.responder_inbound_spi);
    assert_int_equal(ntohl(in_sa->daddr.a4), spec.local_outer_ipv4);
    assert_int_equal(ntohl(out_sa->spi), spec.initiator_inbound_spi);
    assert_int_equal(ntohl(out_sa->daddr.a4), spec.remote_outer_ipv4);

    provider_xfrm_linux_message_plan_clear(&messages);
    provider_xfrm_child_sa_plan_zero_key_material(&plan);
    assert_int_equal(plan.inbound.key_len, 0);
    assert_int_equal(plan.outbound.key_len, 0);
    assert_false(provider_xfrm_linux_child_sa_messages_build(&messages, &plan,
                                                             &result));
    assert_false(result.ok);
    assert_true(provider_xfrm_linux_child_sa_delete_messages_build(
                    &messages, &plan, &result));
    assert_true(result.ok);
    assert_int_equal(messages.count, 5);

    provider_xfrm_linux_message_plan_clear(&messages);
    provider_xfrm_child_sa_plan_clear(&plan);
#endif
}

#if defined(TARGET_LINUX)
struct provider_xfrm_linux_rollback_test_state {
    unsigned int apply_calls;
    unsigned int rollback_calls;
    size_t applied_message_count;
    uint64_t rollback_lease_id;
};

static bool
test_provider_xfrm_linux_apply_fails(
    const struct provider_xfrm_linux_message_plan *messages,
    void *arg,
    struct provider_xfrm_result *result)
{
    struct provider_xfrm_linux_rollback_test_state *test_state = arg;
    assert_non_null(messages);
    assert_non_null(test_state);
    ++test_state->apply_calls;
    test_state->applied_message_count = messages->count;
    result->ok = false;
    snprintf(result->reason, sizeof(result->reason), "%s",
             "forced apply failure");
    return false;
}

static bool
test_provider_xfrm_linux_rollback_records_plan(
    const struct provider_xfrm_child_sa_plan *plan,
    void *arg,
    struct provider_xfrm_result *result)
{
    struct provider_xfrm_linux_rollback_test_state *test_state = arg;
    assert_non_null(plan);
    assert_non_null(test_state);
    ++test_state->rollback_calls;
    test_state->rollback_lease_id = plan->lease_id;
    result->ok = true;
    snprintf(result->reason, sizeof(result->reason), "%s", "rollback ok");
    return true;
}
#endif

static void
test_provider_xfrm_linux_rolls_back_failed_child_sa_apply(void **state)
{
    (void)state;
#if !defined(TARGET_LINUX)
    skip();
#else
    struct provider_xfrm_child_sa_plan plan;
    struct provider_xfrm_result result;
    struct provider_xfrm_child_sa_spec spec = default_child_sa_spec();
    struct provider_xfrm_linux_rollback_test_state test_state;
    CLEAR(test_state);

    assert_true(provider_xfrm_child_sa_plan_build(&plan, &spec, &result));
    assert_false(provider_xfrm_linux_child_sa_plan_apply_with_hooks(
                     &plan, test_provider_xfrm_linux_apply_fails,
                     test_provider_xfrm_linux_rollback_records_plan,
                     &test_state, &result));
    assert_false(result.ok);
    assert_non_null(strstr(result.reason, "forced apply failure"));
    assert_int_equal(test_state.apply_calls, 1);
    assert_int_equal(test_state.applied_message_count,
                     PROVIDER_XFRM_LINUX_MAX_MESSAGES);
    assert_int_equal(test_state.rollback_calls, 1);
    assert_int_equal(test_state.rollback_lease_id, plan.lease_id);

    provider_xfrm_child_sa_plan_clear(&plan);
#endif
}

static void
test_provider_xfrm_linux_rejects_empty_apply(void **state)
{
    (void)state;

    struct provider_xfrm_linux_message_plan messages;
    struct provider_xfrm_result result;
    CLEAR(messages);

    assert_false(provider_xfrm_linux_message_plan_apply(&messages, &result));
    assert_false(result.ok);
#if defined(TARGET_LINUX)
    assert_non_null(strstr(result.reason, "missing XFRM Linux messages"));
#else
    assert_non_null(strstr(result.reason, "unavailable"));
#endif
}

#if defined(TARGET_LINUX)
static int
test_provider_xfrm_linux_apply_in_child_netns(void)
{
    if (unshare(CLONE_NEWNET) != 0)
    {
        return (errno == EPERM || errno == EACCES) ? 77 : 2;
    }

    struct provider_xfrm_child_sa_plan plan;
    struct provider_xfrm_child_sa_plan other_plan;
    struct provider_xfrm_linux_message_plan messages;
    struct provider_xfrm_result result;
    struct provider_xfrm_child_sa_spec spec = default_child_sa_spec();
    struct provider_xfrm_child_sa_spec other_spec = alternate_child_sa_spec();
    CLEAR(plan);
    CLEAR(other_plan);
    CLEAR(messages);

    const bool ret =
        provider_xfrm_child_sa_plan_build(&plan, &spec, &result)
        && provider_xfrm_child_sa_plan_build(&other_plan, &other_spec, &result)
        && provider_xfrm_linux_child_sa_messages_build(&messages, &plan,
                                                       &result)
        && provider_xfrm_linux_message_plan_apply(&messages, &result)
        && provider_xfrm_linux_child_sa_messages_build(&messages, &other_plan,
                                                       &result)
        && provider_xfrm_linux_message_plan_apply(&messages, &result);
    if (ret
        && (!provider_xfrm_linux_child_sa_reconcile_delete(&plan, &result)
            || !provider_xfrm_linux_child_sa_reconcile_delete(&plan, &result)
            || !provider_xfrm_linux_child_sa_delete_messages_build(
                &messages, &other_plan, &result)
            || !provider_xfrm_linux_message_plan_apply(&messages, &result)))
    {
        fprintf(stderr, "XFRM reconcile failed: %s\n", result.reason);
        provider_xfrm_linux_child_sa_reconcile_delete(&other_plan, &result);
        provider_xfrm_linux_child_sa_reconcile_delete(&plan, &result);
        provider_xfrm_linux_message_plan_clear(&messages);
        provider_xfrm_child_sa_plan_clear(&other_plan);
        provider_xfrm_child_sa_plan_clear(&plan);
        return 3;
    }
    if (!ret)
    {
        fprintf(stderr, "XFRM apply failed: %s\n", result.reason);
        provider_xfrm_linux_child_sa_reconcile_delete(&other_plan, &result);
        provider_xfrm_linux_child_sa_reconcile_delete(&plan, &result);
    }
    provider_xfrm_linux_message_plan_clear(&messages);
    provider_xfrm_child_sa_plan_clear(&other_plan);
    provider_xfrm_child_sa_plan_clear(&plan);
    return ret ? 0 : 3;
}
#endif

static void
test_provider_xfrm_linux_applies_in_private_netns(void **state)
{
    (void)state;
#if !defined(TARGET_LINUX)
    skip();
#else
    if (geteuid() != 0)
    {
        skip();
    }

    const pid_t pid = fork();
    assert_true(pid >= 0);
    if (pid == 0)
    {
        _exit(test_provider_xfrm_linux_apply_in_child_netns());
    }

    int status = 0;
    assert_int_equal(waitpid(pid, &status, 0), pid);
    if (WIFEXITED(status) && WEXITSTATUS(status) == 77)
    {
        skip();
    }
    assert_true(WIFEXITED(status));
    assert_int_equal(WEXITSTATUS(status), 0);
#endif
}

int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_provider_xfrm_builds_lease),
        cmocka_unit_test(test_provider_xfrm_rejects_missing_required_fields),
        cmocka_unit_test(test_provider_xfrm_rejects_too_many_selectors),
        cmocka_unit_test(test_provider_xfrm_authorizes_only_exact_selectors),
        cmocka_unit_test(test_provider_xfrm_cleanup_predicate_matches_only_owned_state),
        cmocka_unit_test(test_provider_xfrm_rejects_empty_spi_tuple),
        cmocka_unit_test(test_provider_xfrm_builds_child_sa_plan),
        cmocka_unit_test(test_provider_xfrm_rejects_invalid_child_sa_plan),
        cmocka_unit_test(test_provider_xfrm_linux_builds_child_sa_messages),
        cmocka_unit_test(test_provider_xfrm_linux_rejects_unrepresentable_selectors),
        cmocka_unit_test(test_provider_xfrm_linux_builds_child_sa_delete_messages),
        cmocka_unit_test(test_provider_xfrm_linux_rolls_back_failed_child_sa_apply),
        cmocka_unit_test(test_provider_xfrm_linux_rejects_empty_apply),
        cmocka_unit_test(test_provider_xfrm_linux_applies_in_private_netns),
    };

    return cmocka_run_group_tests_name("provider_xfrm", tests, NULL, NULL);
}
