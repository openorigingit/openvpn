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

#include "provider_helper.h"
#include "test_common.h"

static const char *noop_helper_path;

static struct provider_helper_msg_header
test_header(uint64_t sequence, uint32_t payload_len)
{
    return (struct provider_helper_msg_header) {
        .magic = PROVIDER_HELPER_IPC_MAGIC,
        .version_major = PROVIDER_HELPER_IPC_VERSION_MAJOR,
        .version_minor = PROVIDER_HELPER_IPC_VERSION_MINOR,
        .type = PROVIDER_HELPER_MSG_HELLO,
        .sequence = sequence,
        .correlation_id = 9,
        .payload_len = payload_len,
    };
}

static enum provider_helper_ipc_result
write_and_read_header(const struct provider_helper_msg_header *input,
                      struct provider_helper_msg_header *output,
                      uint64_t *last_sequence)
{
    struct buffer buf = alloc_buf(PROVIDER_HELPER_IPC_HEADER_SIZE);
    assert_true(provider_helper_ipc_write_header(&buf, input));
    assert_int_equal(BLEN(&buf), PROVIDER_HELPER_IPC_HEADER_SIZE);

    const enum provider_helper_ipc_result result =
        provider_helper_ipc_read_header(&buf, output, PROVIDER_HELPER_IPC_MAX_MESSAGE,
                                        last_sequence);
    free_buf(&buf);
    return result;
}

static void
test_provider_helper_framing_roundtrip(void **state)
{
    (void)state;

    const struct provider_helper_msg_header input = test_header(1, 0);
    struct provider_helper_msg_header output;
    uint64_t last_sequence = 0;

    assert_int_equal(write_and_read_header(&input, &output, &last_sequence),
                     PROVIDER_HELPER_IPC_OK);
    assert_int_equal(output.magic, PROVIDER_HELPER_IPC_MAGIC);
    assert_int_equal(output.version_major, PROVIDER_HELPER_IPC_VERSION_MAJOR);
    assert_int_equal(output.version_minor, PROVIDER_HELPER_IPC_VERSION_MINOR);
    assert_int_equal(output.type, PROVIDER_HELPER_MSG_HELLO);
    assert_int_equal(output.sequence, 1);
    assert_int_equal(output.correlation_id, 9);
    assert_int_equal(output.payload_len, 0);
    assert_int_equal(last_sequence, 1);
}

static void
test_provider_helper_rejects_bad_framing(void **state)
{
    (void)state;

    struct provider_helper_msg_header output;
    uint64_t last_sequence = 0;

    struct provider_helper_msg_header oversized =
        test_header(1, PROVIDER_HELPER_IPC_MAX_MESSAGE + 1);
    struct buffer bad_write = alloc_buf(PROVIDER_HELPER_IPC_HEADER_SIZE);
    assert_false(provider_helper_ipc_write_header(&bad_write, &oversized));
    free_buf(&bad_write);

    struct provider_helper_msg_header bad_magic = test_header(1, 0);
    bad_magic.magic = 0;
    assert_int_equal(write_and_read_header(&bad_magic, &output, &last_sequence),
                     PROVIDER_HELPER_IPC_BAD_MAGIC);

    struct provider_helper_msg_header bad_version = test_header(1, 0);
    bad_version.version_major = PROVIDER_HELPER_IPC_VERSION_MAJOR + 1;
    assert_int_equal(write_and_read_header(&bad_version, &output, &last_sequence),
                     PROVIDER_HELPER_IPC_BAD_VERSION);

    struct provider_helper_msg_header seq = test_header(1, 0);
    last_sequence = 1;
    assert_int_equal(write_and_read_header(&seq, &output, &last_sequence),
                     PROVIDER_HELPER_IPC_SEQUENCE_ROLLBACK);
}

static void
test_provider_helper_feature_negotiation(void **state)
{
    (void)state;

    uint64_t negotiated = 0;
    assert_true(provider_helper_negotiate_features(0x05, 0x01, 0x06, &negotiated));
    assert_int_equal(negotiated, 0x05);

    assert_false(provider_helper_negotiate_features(0x01, 0x02, 0, &negotiated));
}

static void
test_provider_helper_processes_partial_header(void **state)
{
    (void)state;

    int fds[2] = { -1, -1 };
    assert_int_equal(socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);

    struct provider_helper_supervisor supervisor;
    provider_helper_supervisor_init(&supervisor);
    supervisor.ipc_fd = fds[0];
    provider_helper_supervisor_set_state(&supervisor, PROVIDER_HELPER_STATE_STARTING);

    struct provider_helper_msg_header hello = test_header(1, 0);
    struct buffer buf = alloc_buf(PROVIDER_HELPER_IPC_HEADER_SIZE);
    assert_true(provider_helper_ipc_write_header(&buf, &hello));
    assert_int_equal(BLEN(&buf), PROVIDER_HELPER_IPC_HEADER_SIZE);

    const size_t half = PROVIDER_HELPER_IPC_HEADER_SIZE / 2;
    assert_int_equal(write(fds[1], BPTR(&buf), half), (ssize_t)half);
    provider_helper_process_event(&supervisor);
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_STARTING);
    assert_int_equal(supervisor.header_len, half);

    assert_int_equal(write(fds[1], BPTR(&buf) + half,
                           (size_t)BLEN(&buf) - half),
                     (ssize_t)((size_t)BLEN(&buf) - half));
    provider_helper_process_event(&supervisor);
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);
    assert_int_equal(supervisor.header_len, 0);
    assert_int_equal(supervisor.last_rx_sequence, 1);

    free_buf(&buf);
    close(fds[1]);
    provider_helper_supervisor_free(&supervisor);
}

static void
test_provider_helper_spawn_noop(void **state)
{
    (void)state;

    struct provider_helper_supervisor supervisor;
    provider_helper_supervisor_init(&supervisor);

    char *const argv[] = { (char *)noop_helper_path, NULL };
    assert_true(provider_helper_supervisor_spawn(&supervisor, noop_helper_path, argv));
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_STARTING);

    for (int i = 0; i < 100 && supervisor.state != PROVIDER_HELPER_STATE_READY; ++i)
    {
        provider_helper_process_event(&supervisor);
        usleep(10000);
    }

    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_READY);
    assert_int_equal(supervisor.last_rx_sequence, 1);
    provider_helper_supervisor_stop(&supervisor);
    assert_int_equal(supervisor.state, PROVIDER_HELPER_STATE_STOPPED);
    assert_int_equal(supervisor.ipc_fd, -1);
}

int
main(void)
{
    if (access("./provider_helper_noop", X_OK) == 0)
    {
        noop_helper_path = "./provider_helper_noop";
    }
    else
    {
        noop_helper_path = "tests/unit_tests/openvpn/provider_helper_noop";
    }

    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_provider_helper_framing_roundtrip),
        cmocka_unit_test(test_provider_helper_rejects_bad_framing),
        cmocka_unit_test(test_provider_helper_feature_negotiation),
        cmocka_unit_test(test_provider_helper_processes_partial_header),
        cmocka_unit_test(test_provider_helper_spawn_noop),
    };

    return cmocka_run_group_tests_name("provider_helper", tests, NULL, NULL);
}
