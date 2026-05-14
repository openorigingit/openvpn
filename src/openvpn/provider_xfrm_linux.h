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

#ifndef PROVIDER_XFRM_LINUX_H
#define PROVIDER_XFRM_LINUX_H

#include "basic.h"
#include "common.h"
#include "provider_xfrm.h"

#define PROVIDER_XFRM_LINUX_MAX_MESSAGES 5
#define PROVIDER_XFRM_LINUX_MESSAGE_SIZE 1024

struct provider_xfrm_linux_message {
    size_t len;
    uint8_t data[PROVIDER_XFRM_LINUX_MESSAGE_SIZE];
};

struct provider_xfrm_linux_message_plan {
    size_t count;
    struct provider_xfrm_linux_message
        messages[PROVIDER_XFRM_LINUX_MAX_MESSAGES];
};

void provider_xfrm_linux_message_plan_clear(
    struct provider_xfrm_linux_message_plan *messages);

bool provider_xfrm_linux_child_sa_messages_build(
    struct provider_xfrm_linux_message_plan *messages,
    const struct provider_xfrm_child_sa_plan *plan,
    struct provider_xfrm_result *result);

bool provider_xfrm_linux_child_sa_delete_messages_build(
    struct provider_xfrm_linux_message_plan *messages,
    const struct provider_xfrm_child_sa_plan *plan,
    struct provider_xfrm_result *result);

bool provider_xfrm_linux_message_plan_apply(
    const struct provider_xfrm_linux_message_plan *messages,
    struct provider_xfrm_result *result);

#endif /* PROVIDER_XFRM_LINUX_H */
