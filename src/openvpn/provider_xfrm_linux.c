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

#include "buffer.h"
#include "provider_xfrm_linux.h"

static void
provider_xfrm_linux_set_error(struct provider_xfrm_result *result,
                              const char *reason)
{
    if (result)
    {
        result->ok = false;
        snprintf(result->reason, sizeof(result->reason), "%s", reason);
    }
}

static void
provider_xfrm_linux_set_errno(struct provider_xfrm_result *result,
                              const char *operation,
                              int error_number)
{
    if (result)
    {
        result->ok = false;
        snprintf(result->reason, sizeof(result->reason), "%s: %s", operation,
                 strerror(error_number));
    }
}

#if defined(TARGET_LINUX)
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/xfrm.h>

#ifndef UDP_ENCAP_ESPINUDP
#define UDP_ENCAP_ESPINUDP 2
#endif

#define PROVIDER_XFRM_LINUX_AEAD_ICV_BITS 128
#define PROVIDER_XFRM_LINUX_DEFAULT_PRIORITY 1000

static bool
provider_xfrm_linux_ipv4_range_to_prefix(uint32_t start, uint32_t end,
                                         uint32_t *prefix_addr,
                                         uint8_t *prefix_len)
{
    if (!prefix_addr || !prefix_len || start > end)
    {
        return false;
    }

    const uint64_t size = (uint64_t)end - (uint64_t)start + 1;
    if ((size & (size - 1)) != 0)
    {
        return false;
    }
    if (size < (1ULL << 32) && ((uint64_t)start % size) != 0)
    {
        return false;
    }
    if (size == (1ULL << 32) && start != 0)
    {
        return false;
    }

    uint8_t host_bits = 0;
    for (uint64_t n = size; n > 1; n >>= 1)
    {
        ++host_bits;
    }
    *prefix_addr = start;
    *prefix_len = (uint8_t)(32 - host_bits);
    return true;
}

static bool
provider_xfrm_linux_port_mask(uint16_t start, uint16_t end,
                              uint16_t *port, uint16_t *mask)
{
    if (!port || !mask || start > end)
    {
        return false;
    }
    if (start == 0 && end == UINT16_MAX)
    {
        *port = 0;
        *mask = 0;
        return true;
    }
    if (start == end)
    {
        *port = start;
        *mask = UINT16_MAX;
        return true;
    }
    return false;
}

static bool
provider_xfrm_linux_selector_build(
    struct xfrm_selector *selector,
    const struct provider_xfrm_ipv4_selector *src,
    const struct provider_xfrm_ipv4_selector *dst,
    struct provider_xfrm_result *result)
{
    uint32_t src_addr = 0;
    uint32_t dst_addr = 0;
    uint8_t src_prefix = 0;
    uint8_t dst_prefix = 0;
    uint16_t src_port = 0;
    uint16_t src_mask = 0;
    uint16_t dst_port = 0;
    uint16_t dst_mask = 0;

    if (!selector || !src || !dst
        || !provider_xfrm_linux_ipv4_range_to_prefix(
            src->start_addr, src->end_addr, &src_addr, &src_prefix)
        || !provider_xfrm_linux_ipv4_range_to_prefix(
            dst->start_addr, dst->end_addr, &dst_addr, &dst_prefix))
    {
        provider_xfrm_linux_set_error(
            result,
            "XFRM Linux backend requires CIDR-compatible IPv4 selectors");
        return false;
    }
    if (!provider_xfrm_linux_port_mask(src->start_port, src->end_port,
                                       &src_port, &src_mask)
        || !provider_xfrm_linux_port_mask(dst->start_port, dst->end_port,
                                          &dst_port, &dst_mask))
    {
        provider_xfrm_linux_set_error(
            result,
            "XFRM Linux backend requires exact or wildcard port selectors");
        return false;
    }

    CLEAR(*selector);
    selector->family = AF_INET;
    selector->saddr.a4 = htonl(src_addr);
    selector->daddr.a4 = htonl(dst_addr);
    selector->prefixlen_s = src_prefix;
    selector->prefixlen_d = dst_prefix;
    selector->sport = htons(src_port);
    selector->sport_mask = htons(src_mask);
    selector->dport = htons(dst_port);
    selector->dport_mask = htons(dst_mask);
    selector->proto = src->ip_protocol_id == dst->ip_protocol_id
                      ? src->ip_protocol_id
                      : 0;
    return true;
}

static void
provider_xfrm_linux_lifetime_default(struct xfrm_lifetime_cfg *lft)
{
    CLEAR(*lft);
    lft->soft_byte_limit = XFRM_INF;
    lft->hard_byte_limit = XFRM_INF;
    lft->soft_packet_limit = XFRM_INF;
    lft->hard_packet_limit = XFRM_INF;
}

static bool
provider_xfrm_linux_message_start_flags(
    struct provider_xfrm_linux_message *message,
    uint16_t type,
    uint16_t flags,
    const void *payload,
    size_t payload_len)
{
    if (!message || !payload
        || NLMSG_SPACE(payload_len) > sizeof(message->data))
    {
        return false;
    }

    CLEAR(*message);
    const size_t nlmsg_len = NLMSG_LENGTH(payload_len);
    struct nlmsghdr *nlh = (struct nlmsghdr *)message->data;
    nlh->nlmsg_len = (uint32_t)nlmsg_len;
    nlh->nlmsg_type = type;
    nlh->nlmsg_flags = flags;
    memcpy(NLMSG_DATA(nlh), payload, payload_len);
    message->len = nlh->nlmsg_len;
    return true;
}

static bool
provider_xfrm_linux_message_start(struct provider_xfrm_linux_message *message,
                                  uint16_t type,
                                  const void *payload,
                                  size_t payload_len)
{
    return provider_xfrm_linux_message_start_flags(
        message, type, NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        payload, payload_len);
}

static bool
provider_xfrm_linux_message_add_attr(
    struct provider_xfrm_linux_message *message,
    uint16_t type,
    const void *payload,
    size_t payload_len)
{
    if (!message || !message->len || !payload)
    {
        return false;
    }

    struct nlmsghdr *nlh = (struct nlmsghdr *)message->data;
    const size_t attr_len = RTA_LENGTH(payload_len);
    const size_t new_len = NLMSG_ALIGN(nlh->nlmsg_len) + RTA_ALIGN(attr_len);
    if (new_len > sizeof(message->data))
    {
        return false;
    }

    struct rtattr *rta =
        (struct rtattr *)(message->data + NLMSG_ALIGN(nlh->nlmsg_len));
    rta->rta_type = type;
    rta->rta_len = (unsigned short)attr_len;
    memcpy(RTA_DATA(rta), payload, payload_len);
    nlh->nlmsg_len = (uint32_t)new_len;
    message->len = new_len;
    return true;
}

static bool
provider_xfrm_linux_add_mark_and_if_id(
    struct provider_xfrm_linux_message *message,
    uint32_t mark_value,
    uint32_t mark_mask,
    uint32_t if_id)
{
    const struct xfrm_mark mark = {
        .v = mark_value,
        .m = mark_mask,
    };
    if (!provider_xfrm_linux_message_add_attr(message, XFRMA_MARK, &mark,
                                              sizeof(mark)))
    {
        return false;
    }
    return !if_id
           || provider_xfrm_linux_message_add_attr(message, XFRMA_IF_ID,
                                                   &if_id, sizeof(if_id));
}

static bool
provider_xfrm_linux_state_identity_valid(
    const struct provider_xfrm_child_sa_state *state,
    enum provider_xfrm_direction direction)
{
    return state && state->direction == direction && state->src_outer_ipv4
           && state->dst_outer_ipv4 && state->src_outer_port
           && state->dst_outer_port && state->spi && state->reqid
           && state->mark_mask;
}

static bool
provider_xfrm_linux_state_key_valid(
    const struct provider_xfrm_child_sa_state *state,
    enum provider_xfrm_direction direction)
{
    return provider_xfrm_linux_state_identity_valid(state, direction)
           && state->cipher == PROVIDER_XFRM_CIPHER_AES_GCM_16
           && state->key_len && state->key_len <= sizeof(state->key);
}

static bool
provider_xfrm_linux_policy_state_valid(
    const struct provider_xfrm_child_sa_state *state,
    uint8_t policy_dir)
{
    if (policy_dir == XFRM_POLICY_OUT)
    {
        return provider_xfrm_linux_state_identity_valid(
            state, PROVIDER_XFRM_DIRECTION_OUT);
    }
    if (policy_dir == XFRM_POLICY_IN || policy_dir == XFRM_POLICY_FWD)
    {
        return provider_xfrm_linux_state_identity_valid(
            state, PROVIDER_XFRM_DIRECTION_IN);
    }
    return false;
}

static bool
provider_xfrm_linux_sa_message_build(
    struct provider_xfrm_linux_message *message,
    const struct provider_xfrm_child_sa_state *state,
    enum provider_xfrm_direction direction,
    struct provider_xfrm_result *result)
{
    if (!provider_xfrm_linux_state_key_valid(state, direction))
    {
        provider_xfrm_linux_set_error(result, "invalid XFRM Linux SA state");
        return false;
    }

    struct xfrm_usersa_info sa;
    CLEAR(sa);
    if (!provider_xfrm_linux_selector_build(&sa.sel, &state->src_ts,
                                            &state->dst_ts, result))
    {
        return false;
    }
    sa.id.daddr.a4 = htonl(state->dst_outer_ipv4);
    sa.id.spi = htonl(state->spi);
    sa.id.proto = IPPROTO_ESP;
    sa.saddr.a4 = htonl(state->src_outer_ipv4);
    provider_xfrm_linux_lifetime_default(&sa.lft);
    sa.reqid = state->reqid;
    sa.family = AF_INET;
    sa.mode = XFRM_MODE_TUNNEL;
    sa.replay_window = 32;

    if (!provider_xfrm_linux_message_start(message, XFRM_MSG_NEWSA, &sa,
                                           sizeof(sa)))
    {
        provider_xfrm_linux_set_error(result, "failed to build XFRM NEWSA");
        return false;
    }

    uint8_t aead_buf[sizeof(struct xfrm_algo_aead)
                     + PROVIDER_XFRM_KEYMAT_MAX_BYTES];
    CLEAR(aead_buf);
    struct xfrm_algo_aead *aead = (struct xfrm_algo_aead *)aead_buf;
    snprintf(aead->alg_name, sizeof(aead->alg_name), "rfc4106(gcm(aes))");
    aead->alg_key_len = (unsigned int)(state->key_len * 8);
    aead->alg_icv_len = PROVIDER_XFRM_LINUX_AEAD_ICV_BITS;
    memcpy(aead->alg_key, state->key, state->key_len);
    const bool aead_added = provider_xfrm_linux_message_add_attr(
        message, XFRMA_ALG_AEAD, aead_buf, sizeof(*aead) + state->key_len);
    secure_memzero(aead_buf, sizeof(aead_buf));
    if (!aead_added)
    {
        provider_xfrm_linux_set_error(result, "failed to add XFRM AEAD key");
        return false;
    }

    const struct xfrm_encap_tmpl encap = {
        .encap_type = UDP_ENCAP_ESPINUDP,
        .encap_sport = htons(state->src_outer_port),
        .encap_dport = htons(state->dst_outer_port),
    };
    if (!provider_xfrm_linux_message_add_attr(message, XFRMA_ENCAP, &encap,
                                              sizeof(encap))
        || !provider_xfrm_linux_add_mark_and_if_id(
            message, state->mark_value, state->mark_mask, state->if_id))
    {
        provider_xfrm_linux_set_error(result,
                                      "failed to add XFRM SA attributes");
        return false;
    }

    return true;
}

static bool
provider_xfrm_linux_sa_delete_message_build(
    struct provider_xfrm_linux_message *message,
    const struct provider_xfrm_child_sa_state *state,
    enum provider_xfrm_direction direction,
    struct provider_xfrm_result *result)
{
    if (!provider_xfrm_linux_state_identity_valid(state, direction))
    {
        provider_xfrm_linux_set_error(result,
                                      "invalid XFRM Linux SA delete state");
        return false;
    }

    struct xfrm_usersa_id sa_id;
    CLEAR(sa_id);
    sa_id.daddr.a4 = htonl(state->dst_outer_ipv4);
    sa_id.spi = htonl(state->spi);
    sa_id.proto = IPPROTO_ESP;
    sa_id.family = AF_INET;

    if (!provider_xfrm_linux_message_start_flags(
            message, XFRM_MSG_DELSA, NLM_F_REQUEST | NLM_F_ACK, &sa_id,
            sizeof(sa_id)))
    {
        provider_xfrm_linux_set_error(result, "failed to build XFRM DELSA");
        return false;
    }
    if (!provider_xfrm_linux_add_mark_and_if_id(
            message, state->mark_value, state->mark_mask, state->if_id))
    {
        provider_xfrm_linux_set_error(result,
                                      "failed to add XFRM DELSA attributes");
        return false;
    }

    return true;
}

static void
provider_xfrm_linux_tmpl_from_state(
    struct xfrm_user_tmpl *tmpl,
    const struct provider_xfrm_child_sa_state *state)
{
    CLEAR(*tmpl);
    tmpl->id.daddr.a4 = htonl(state->dst_outer_ipv4);
    tmpl->id.spi = htonl(state->spi);
    tmpl->id.proto = IPPROTO_ESP;
    tmpl->family = AF_INET;
    tmpl->saddr.a4 = htonl(state->src_outer_ipv4);
    tmpl->reqid = state->reqid;
    tmpl->mode = XFRM_MODE_TUNNEL;
    tmpl->share = XFRM_SHARE_UNIQUE;
}

static bool
provider_xfrm_linux_policy_message_build(
    struct provider_xfrm_linux_message *message,
    const struct provider_xfrm_child_sa_state *state,
    uint8_t dir,
    struct provider_xfrm_result *result)
{
    if (!provider_xfrm_linux_policy_state_valid(state, dir))
    {
        provider_xfrm_linux_set_error(result,
                                      "invalid XFRM Linux policy state");
        return false;
    }

    struct xfrm_userpolicy_info policy;
    CLEAR(policy);
    if (!provider_xfrm_linux_selector_build(&policy.sel, &state->src_ts,
                                            &state->dst_ts, result))
    {
        return false;
    }
    provider_xfrm_linux_lifetime_default(&policy.lft);
    policy.priority = PROVIDER_XFRM_LINUX_DEFAULT_PRIORITY;
    policy.dir = dir;
    policy.action = XFRM_POLICY_ALLOW;
    policy.share = XFRM_SHARE_UNIQUE;

    if (!provider_xfrm_linux_message_start(message, XFRM_MSG_NEWPOLICY,
                                           &policy, sizeof(policy)))
    {
        provider_xfrm_linux_set_error(result,
                                      "failed to build XFRM NEWPOLICY");
        return false;
    }

    struct xfrm_user_tmpl tmpl;
    provider_xfrm_linux_tmpl_from_state(&tmpl, state);
    if (!provider_xfrm_linux_message_add_attr(message, XFRMA_TMPL, &tmpl,
                                              sizeof(tmpl))
        || !provider_xfrm_linux_add_mark_and_if_id(
            message, state->mark_value, state->mark_mask, state->if_id))
    {
        provider_xfrm_linux_set_error(result,
                                      "failed to add XFRM policy attributes");
        return false;
    }

    return true;
}

static bool
provider_xfrm_linux_policy_delete_message_build(
    struct provider_xfrm_linux_message *message,
    const struct provider_xfrm_child_sa_state *state,
    uint8_t dir,
    struct provider_xfrm_result *result)
{
    if (!provider_xfrm_linux_policy_state_valid(state, dir))
    {
        provider_xfrm_linux_set_error(result,
                                      "invalid XFRM Linux policy delete state");
        return false;
    }

    struct xfrm_userpolicy_id policy_id;
    CLEAR(policy_id);
    if (!provider_xfrm_linux_selector_build(&policy_id.sel, &state->src_ts,
                                            &state->dst_ts, result))
    {
        return false;
    }
    policy_id.dir = dir;

    if (!provider_xfrm_linux_message_start_flags(
            message, XFRM_MSG_DELPOLICY, NLM_F_REQUEST | NLM_F_ACK,
            &policy_id, sizeof(policy_id)))
    {
        provider_xfrm_linux_set_error(result,
                                      "failed to build XFRM DELPOLICY");
        return false;
    }
    if (!provider_xfrm_linux_add_mark_and_if_id(
            message, state->mark_value, state->mark_mask, state->if_id))
    {
        provider_xfrm_linux_set_error(
            result, "failed to add XFRM DELPOLICY attributes");
        return false;
    }

    return true;
}

void
provider_xfrm_linux_message_plan_clear(
    struct provider_xfrm_linux_message_plan *messages)
{
    if (messages)
    {
        secure_memzero(messages, sizeof(*messages));
    }
}

bool
provider_xfrm_linux_child_sa_messages_build(
    struct provider_xfrm_linux_message_plan *messages,
    const struct provider_xfrm_child_sa_plan *plan,
    struct provider_xfrm_result *result)
{
    provider_xfrm_result_init(result);
    provider_xfrm_linux_message_plan_clear(messages);
    if (!messages || !plan || !plan->lease_id || !plan->provider_session_id
        || !plan->policy_revision)
    {
        provider_xfrm_linux_set_error(result,
                                      "missing XFRM Linux message plan input");
        return false;
    }

    if (!provider_xfrm_linux_sa_message_build(
            &messages->messages[messages->count++], &plan->inbound,
            PROVIDER_XFRM_DIRECTION_IN, result)
        || !provider_xfrm_linux_sa_message_build(
            &messages->messages[messages->count++], &plan->outbound,
            PROVIDER_XFRM_DIRECTION_OUT, result)
        || !provider_xfrm_linux_policy_message_build(
            &messages->messages[messages->count++], &plan->inbound,
            XFRM_POLICY_IN, result)
        || !provider_xfrm_linux_policy_message_build(
            &messages->messages[messages->count++], &plan->inbound,
            XFRM_POLICY_FWD, result)
        || !provider_xfrm_linux_policy_message_build(
            &messages->messages[messages->count++], &plan->outbound,
            XFRM_POLICY_OUT, result))
    {
        provider_xfrm_linux_message_plan_clear(messages);
        return false;
    }

    return true;
}

bool
provider_xfrm_linux_child_sa_delete_messages_build(
    struct provider_xfrm_linux_message_plan *messages,
    const struct provider_xfrm_child_sa_plan *plan,
    struct provider_xfrm_result *result)
{
    provider_xfrm_result_init(result);
    provider_xfrm_linux_message_plan_clear(messages);
    if (!messages || !plan || !plan->lease_id || !plan->provider_session_id
        || !plan->policy_revision)
    {
        provider_xfrm_linux_set_error(
            result, "missing XFRM Linux delete message plan input");
        return false;
    }

    if (!provider_xfrm_linux_policy_delete_message_build(
            &messages->messages[messages->count++], &plan->inbound,
            XFRM_POLICY_IN, result)
        || !provider_xfrm_linux_policy_delete_message_build(
            &messages->messages[messages->count++], &plan->inbound,
            XFRM_POLICY_FWD, result)
        || !provider_xfrm_linux_policy_delete_message_build(
            &messages->messages[messages->count++], &plan->outbound,
            XFRM_POLICY_OUT, result)
        || !provider_xfrm_linux_sa_delete_message_build(
            &messages->messages[messages->count++], &plan->inbound,
            PROVIDER_XFRM_DIRECTION_IN, result)
        || !provider_xfrm_linux_sa_delete_message_build(
            &messages->messages[messages->count++], &plan->outbound,
            PROVIDER_XFRM_DIRECTION_OUT, result))
    {
        provider_xfrm_linux_message_plan_clear(messages);
        return false;
    }

    return true;
}

static int
provider_xfrm_linux_netlink_open(struct provider_xfrm_result *result)
{
    const int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_XFRM);
    if (fd < 0)
    {
        provider_xfrm_linux_set_errno(result, "open NETLINK_XFRM socket",
                                      errno);
        return -1;
    }

    if (fcntl(fd, F_SETFD, FD_CLOEXEC) < 0)
    {
        provider_xfrm_linux_set_errno(result, "set NETLINK_XFRM close-on-exec",
                                      errno);
        close(fd);
        return -1;
    }

    struct sockaddr_nl local;
    CLEAR(local);
    local.nl_family = AF_NETLINK;
    if (bind(fd, (struct sockaddr *)&local, sizeof(local)) < 0)
    {
        provider_xfrm_linux_set_errno(result, "bind NETLINK_XFRM socket",
                                      errno);
        close(fd);
        return -1;
    }

    return fd;
}

static bool
provider_xfrm_linux_wait_ack(int fd, uint32_t sequence,
                             struct provider_xfrm_result *result)
{
    uint8_t buf[8192];
    struct sockaddr_nl peer;
    struct iovec iov = {
        .iov_base = buf,
        .iov_len = sizeof(buf),
    };
    struct msghdr msg = {
        .msg_name = &peer,
        .msg_namelen = sizeof(peer),
        .msg_iov = &iov,
        .msg_iovlen = 1,
    };

    while (true)
    {
        CLEAR(peer);
        iov.iov_base = buf;
        iov.iov_len = sizeof(buf);
        msg.msg_namelen = sizeof(peer);
        msg.msg_flags = 0;
        const ssize_t n = recvmsg(fd, &msg, 0);
        if (n < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            provider_xfrm_linux_set_errno(result, "receive NETLINK_XFRM ack",
                                          errno);
            return false;
        }
        if (n == 0 || msg.msg_flags & MSG_TRUNC)
        {
            provider_xfrm_linux_set_error(result,
                                          "invalid NETLINK_XFRM ack");
            return false;
        }

        int remaining = (int)n;
        for (struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
             NLMSG_OK(nlh, remaining);
             nlh = NLMSG_NEXT(nlh, remaining))
        {
            if (nlh->nlmsg_seq != sequence)
            {
                continue;
            }
            if (nlh->nlmsg_type == NLMSG_DONE)
            {
                return true;
            }
            if (nlh->nlmsg_type != NLMSG_ERROR)
            {
                continue;
            }

            const struct nlmsgerr *err = NLMSG_DATA(nlh);
            if (nlh->nlmsg_len < NLMSG_LENGTH(sizeof(*err)))
            {
                provider_xfrm_linux_set_error(result,
                                              "truncated NETLINK_XFRM error");
                return false;
            }
            if (!err->error)
            {
                return true;
            }
            provider_xfrm_linux_set_errno(result, "NETLINK_XFRM operation",
                                          -err->error);
            return false;
        }
    }
}

static bool
provider_xfrm_linux_message_apply(int fd,
                                  const struct provider_xfrm_linux_message *message,
                                  uint32_t sequence,
                                  struct provider_xfrm_result *result)
{
    if (!message || message->len < sizeof(struct nlmsghdr)
        || message->len > sizeof(message->data))
    {
        provider_xfrm_linux_set_error(result, "invalid XFRM Linux message");
        return false;
    }

    uint8_t data[PROVIDER_XFRM_LINUX_MESSAGE_SIZE];
    memcpy(data, message->data, message->len);
    struct nlmsghdr *nlh = (struct nlmsghdr *)data;
    nlh->nlmsg_seq = sequence;
    nlh->nlmsg_flags |= NLM_F_ACK;

    struct sockaddr_nl peer;
    CLEAR(peer);
    peer.nl_family = AF_NETLINK;
    struct iovec iov = {
        .iov_base = data,
        .iov_len = message->len,
    };
    struct msghdr msg = {
        .msg_name = &peer,
        .msg_namelen = sizeof(peer),
        .msg_iov = &iov,
        .msg_iovlen = 1,
    };

    bool ret = false;
    while (true)
    {
        const ssize_t n = sendmsg(fd, &msg, 0);
        if (n < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            provider_xfrm_linux_set_errno(result, "send NETLINK_XFRM message",
                                          errno);
            goto cleanup;
        }
        if ((size_t)n != message->len)
        {
            provider_xfrm_linux_set_error(result,
                                          "short NETLINK_XFRM message send");
            goto cleanup;
        }
        break;
    }

    ret = provider_xfrm_linux_wait_ack(fd, sequence, result);

cleanup:
    secure_memzero(data, sizeof(data));
    return ret;
}

bool
provider_xfrm_linux_message_plan_apply(
    const struct provider_xfrm_linux_message_plan *messages,
    struct provider_xfrm_result *result)
{
    provider_xfrm_result_init(result);
    if (!messages || !messages->count
        || messages->count > PROVIDER_XFRM_LINUX_MAX_MESSAGES)
    {
        provider_xfrm_linux_set_error(result,
                                      "missing XFRM Linux messages to apply");
        return false;
    }

    const int fd = provider_xfrm_linux_netlink_open(result);
    if (fd < 0)
    {
        return false;
    }

    bool ret = true;
    for (size_t i = 0; i < messages->count; ++i)
    {
        if (!provider_xfrm_linux_message_apply(
                fd, &messages->messages[i], (uint32_t)(i + 1), result))
        {
            ret = false;
            break;
        }
    }
    close(fd);
    return ret;
}

#else  /* if defined(TARGET_LINUX) */

void
provider_xfrm_linux_message_plan_clear(
    struct provider_xfrm_linux_message_plan *messages)
{
    if (messages)
    {
        secure_memzero(messages, sizeof(*messages));
    }
}

bool
provider_xfrm_linux_child_sa_messages_build(
    struct provider_xfrm_linux_message_plan *messages,
    const struct provider_xfrm_child_sa_plan *plan,
    struct provider_xfrm_result *result)
{
    (void)plan;
    provider_xfrm_result_init(result);
    provider_xfrm_linux_message_plan_clear(messages);
    provider_xfrm_linux_set_error(result,
                                  "Linux XFRM backend is unavailable");
    return false;
}

bool
provider_xfrm_linux_child_sa_delete_messages_build(
    struct provider_xfrm_linux_message_plan *messages,
    const struct provider_xfrm_child_sa_plan *plan,
    struct provider_xfrm_result *result)
{
    (void)messages;
    (void)plan;
    provider_xfrm_result_init(result);
    provider_xfrm_linux_set_error(result,
                                  "Linux XFRM backend is unavailable");
    return false;
}

bool
provider_xfrm_linux_message_plan_apply(
    const struct provider_xfrm_linux_message_plan *messages,
    struct provider_xfrm_result *result)
{
    (void)messages;
    provider_xfrm_result_init(result);
    provider_xfrm_linux_set_error(result,
                                  "Linux XFRM backend is unavailable");
    return false;
}

#endif /* defined(TARGET_LINUX) */
