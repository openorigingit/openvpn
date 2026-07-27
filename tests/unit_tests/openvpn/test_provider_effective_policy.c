/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
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

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include "provider_effective_policy.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static const char digest_a[] =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
static const char digest_b[] =
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
static const char fingerprint_a[] =
    "sha256:1111111111111111111111111111111111111111111111111111111111111111";
static const char fingerprint_b[] =
    "sha256:2222222222222222222222222222222222222222222222222222222222222222";
static const char fingerprint_c[] =
    "sha256:3333333333333333333333333333333333333333333333333333333333333333";

struct effective_policy_fixture
{
    char directory[256];
    char path[320];
    struct provider_effective_policy_store store;
};

static int
effective_policy_setup(void **state)
{
    struct effective_policy_fixture *fixture = calloc(1, sizeof(*fixture));
    assert_non_null(fixture);
    const char *tmp_dir = getenv("TMPDIR");
    if (!tmp_dir || !*tmp_dir)
    {
        tmp_dir = "/tmp";
    }
    assert_true(snprintf(fixture->directory, sizeof(fixture->directory),
                         "%s/openvpn-effective-policy-XXXXXX", tmp_dir)
                > 0);
    assert_non_null(mkdtemp(fixture->directory));
    assert_true(snprintf(fixture->path, sizeof(fixture->path), "%s/state",
                         fixture->directory)
                > 0);

    char reason[256];
    assert_int_equal(provider_effective_policy_init(
                         &fixture->store, fixture->path, reason, sizeof(reason)),
                     PROVIDER_EFFECTIVE_POLICY_OK);
    *state = fixture;
    return 0;
}

static int
effective_policy_teardown(void **state)
{
    struct effective_policy_fixture *fixture = *state;
    provider_effective_policy_free(&fixture->store);
    (void)unlink(fixture->path);
    (void)rmdir(fixture->directory);
    free(fixture);
    return 0;
}

static enum provider_effective_policy_result
accept_snapshot(struct effective_policy_fixture *fixture, const char *user,
                uint64_t revision, const char *digest, const char *object_id)
{
    char reason[256];
    return provider_effective_policy_accept_snapshot(
        &fixture->store, user, revision, digest, object_id, reason,
        sizeof(reason));
}

static enum provider_effective_policy_result
bind_child(struct effective_policy_fixture *fixture, const char *fingerprint,
           const char *user, const char *device, uint64_t generation)
{
    char reason[256];
    return provider_effective_policy_bind_child(
        &fixture->store, fingerprint, user, device, generation, reason,
        sizeof(reason));
}

static void
reload_store(struct effective_policy_fixture *fixture)
{
    char reason[256];
    provider_effective_policy_free(&fixture->store);
    assert_int_equal(provider_effective_policy_init(
                         &fixture->store, fixture->path, reason, sizeof(reason)),
                     PROVIDER_EFFECTIVE_POLICY_OK);
    assert_int_equal(provider_effective_policy_load(
                         &fixture->store, reason, sizeof(reason)),
                     PROVIDER_EFFECTIVE_POLICY_OK);
}

static void
test_effective_policy_result_names_are_stable(void **state)
{
    (void)state;
    assert_string_equal(provider_effective_policy_result_name(
                            PROVIDER_EFFECTIVE_POLICY_OK),
                        "ok");
    assert_string_equal(provider_effective_policy_result_name(
                            PROVIDER_EFFECTIVE_POLICY_IDEMPOTENT),
                        "idempotent");
    assert_string_equal(provider_effective_policy_result_name(
                            PROVIDER_EFFECTIVE_POLICY_INVALID),
                        "invalid");
    assert_string_equal(provider_effective_policy_result_name(
                            PROVIDER_EFFECTIVE_POLICY_NOT_FOUND),
                        "not_found");
    assert_string_equal(provider_effective_policy_result_name(
                            PROVIDER_EFFECTIVE_POLICY_CONFLICT),
                        "conflict");
    assert_string_equal(provider_effective_policy_result_name(
                            PROVIDER_EFFECTIVE_POLICY_STALE),
                        "stale");
    assert_string_equal(provider_effective_policy_result_name(
                            PROVIDER_EFFECTIVE_POLICY_IO_ERROR),
                        "io_error");
    assert_string_equal(provider_effective_policy_result_name(
                            PROVIDER_EFFECTIVE_POLICY_NO_MEMORY),
                        "no_memory");
}

static void
test_effective_policy_accepts_valid_snapshot(void **state)
{
    struct effective_policy_fixture *fixture = *state;
    assert_int_equal(
        accept_snapshot(fixture, "child-1", 1, digest_a,
                        "saving-jane://policy/child-1/1"),
        PROVIDER_EFFECTIVE_POLICY_OK);

    struct provider_effective_policy_snapshot snapshot;
    assert_true(provider_effective_policy_snapshot_status(
        &fixture->store, "child-1", &snapshot));
    assert_int_equal(snapshot.source_revision, 1);
    assert_string_equal(snapshot.sha256_digest, digest_a);
    assert_string_equal(snapshot.object_id,
                        "saving-jane://policy/child-1/1");
    assert_int_equal(fixture->store.binding_count, 0);
}

static void
test_effective_policy_duplicate_stale_and_conflict(void **state)
{
    struct effective_policy_fixture *fixture = *state;
    assert_int_equal(
        accept_snapshot(fixture, "child-1", 5, digest_a,
                        "saving-jane://policy/child-1/5"),
        PROVIDER_EFFECTIVE_POLICY_OK);
    assert_int_equal(
        accept_snapshot(fixture, "child-1", 5, digest_a,
                        "saving-jane://policy/child-1/5"),
        PROVIDER_EFFECTIVE_POLICY_IDEMPOTENT);
    assert_int_equal(
        accept_snapshot(fixture, "child-1", 5, digest_a,
                        "saving-jane://another-reference"),
        PROVIDER_EFFECTIVE_POLICY_CONFLICT);
    assert_int_equal(
        accept_snapshot(fixture, "child-1", 5, digest_b,
                        "saving-jane://policy/child-1/5"),
        PROVIDER_EFFECTIVE_POLICY_CONFLICT);
    assert_int_equal(
        accept_snapshot(fixture, "child-1", 4, digest_a,
                        "saving-jane://policy/child-1/4"),
        PROVIDER_EFFECTIVE_POLICY_STALE);

    struct provider_effective_policy_snapshot snapshot;
    assert_true(provider_effective_policy_snapshot_status(
        &fixture->store, "child-1", &snapshot));
    assert_int_equal(snapshot.source_revision, 5);
    assert_string_equal(snapshot.sha256_digest, digest_a);
    assert_string_equal(snapshot.object_id,
                        "saving-jane://policy/child-1/5");
}

static void
test_effective_policy_rejects_bad_metadata(void **state)
{
    struct effective_policy_fixture *fixture = *state;
    char long_user[PROVIDER_EFFECTIVE_POLICY_USER_ID_SIZE + 1];
    memset(long_user, 'x', sizeof(long_user) - 1);
    long_user[sizeof(long_user) - 1] = '\0';

    assert_int_equal(
        accept_snapshot(fixture, "bad user", 1, digest_a,
                        "saving-jane://policy/1"),
        PROVIDER_EFFECTIVE_POLICY_INVALID);
    assert_int_equal(
        accept_snapshot(fixture, long_user, 1, digest_a,
                        "saving-jane://policy/1"),
        PROVIDER_EFFECTIVE_POLICY_INVALID);
    assert_int_equal(
        accept_snapshot(fixture, "child-1", 0, digest_a,
                        "saving-jane://policy/1"),
        PROVIDER_EFFECTIVE_POLICY_INVALID);
    assert_int_equal(
        accept_snapshot(fixture, "child-1", 1, "not-a-digest",
                        "saving-jane://policy/1"),
        PROVIDER_EFFECTIVE_POLICY_INVALID);
    assert_int_equal(
        accept_snapshot(fixture, "child-1", 1, digest_a,
                        "saving jane policy"),
        PROVIDER_EFFECTIVE_POLICY_INVALID);
    assert_int_equal(bind_child(fixture, "sha256:short", "child-1", "phone", 1),
                     PROVIDER_EFFECTIVE_POLICY_INVALID);
    assert_int_equal(bind_child(fixture, fingerprint_a, "child-1", "bad device", 1),
                     PROVIDER_EFFECTIVE_POLICY_INVALID);
    assert_int_equal(bind_child(fixture, fingerprint_a, "child-1", "phone", 0),
                     PROVIDER_EFFECTIVE_POLICY_INVALID);
    assert_int_equal(fixture->store.snapshot_count, 0);
    assert_int_equal(fixture->store.binding_count, 0);
}

static void
test_effective_policy_user_fanout_is_isolated(void **state)
{
    struct effective_policy_fixture *fixture = *state;
    assert_int_equal(bind_child(fixture, fingerprint_a, "child-a", "phone-a", 1),
                     PROVIDER_EFFECTIVE_POLICY_OK);
    assert_int_equal(bind_child(fixture, fingerprint_b, "child-b", "phone-b", 1),
                     PROVIDER_EFFECTIVE_POLICY_OK);
    assert_int_equal(
        accept_snapshot(fixture, "child-a", 7, digest_a,
                        "saving-jane://policy/child-a/7"),
        PROVIDER_EFFECTIVE_POLICY_OK);

    struct provider_effective_policy_binding a;
    struct provider_effective_policy_binding b;
    assert_true(provider_effective_policy_binding_status(
        &fixture->store, fingerprint_a, &a));
    assert_true(provider_effective_policy_binding_status(
        &fixture->store, fingerprint_b, &b));
    assert_int_equal(a.desired_revision, 7);
    assert_int_equal(a.projection_state,
                     PROVIDER_EFFECTIVE_POLICY_PROJECTION_PENDING);
    assert_int_equal(b.desired_revision, 0);
    assert_int_equal(b.projection_state,
                     PROVIDER_EFFECTIVE_POLICY_PROJECTION_APPLIED);
    assert_int_equal(provider_effective_policy_binding_enumerate(
                         &fixture->store, "child-a", true, 0, NULL),
                     1);
    assert_int_equal(provider_effective_policy_binding_enumerate(
                         &fixture->store, "child-b", true, 0, NULL),
                     1);
}

static void
test_effective_policy_unbound_child_is_excluded(void **state)
{
    struct effective_policy_fixture *fixture = *state;
    char reason[256];
    assert_int_equal(
        accept_snapshot(fixture, "child-1", 1, digest_a,
                        "saving-jane://policy/child-1/1"),
        PROVIDER_EFFECTIVE_POLICY_OK);
    assert_int_equal(bind_child(fixture, fingerprint_a, "child-1", "phone", 1),
                     PROVIDER_EFFECTIVE_POLICY_OK);
    assert_int_equal(provider_effective_policy_unbind_child(
                         &fixture->store, fingerprint_a, reason, sizeof(reason)),
                     PROVIDER_EFFECTIVE_POLICY_OK);
    assert_int_equal(
        accept_snapshot(fixture, "child-1", 2, digest_b,
                        "saving-jane://policy/child-1/2"),
        PROVIDER_EFFECTIVE_POLICY_OK);

    struct provider_effective_policy_binding binding;
    assert_true(provider_effective_policy_binding_status(
        &fixture->store, fingerprint_a, &binding));
    assert_false(binding.active);
    assert_int_equal(binding.desired_revision, 1);
    assert_int_equal(provider_effective_policy_binding_enumerate(
                         &fixture->store, "child-1", true, 0, NULL),
                     0);
    assert_int_equal(provider_effective_policy_binding_enumerate(
                         &fixture->store, "child-1", false, 0, NULL),
                     1);
}

static void
test_effective_policy_future_binding_inherits_revision(void **state)
{
    struct effective_policy_fixture *fixture = *state;
    assert_int_equal(
        accept_snapshot(fixture, "child-1", 9, digest_a,
                        "saving-jane://policy/child-1/9"),
        PROVIDER_EFFECTIVE_POLICY_OK);
    assert_int_equal(bind_child(fixture, fingerprint_a, "child-1", "tablet", 3),
                     PROVIDER_EFFECTIVE_POLICY_OK);

    struct provider_effective_policy_binding binding;
    assert_true(provider_effective_policy_binding_status(
        &fixture->store, fingerprint_a, &binding));
    assert_true(binding.active);
    assert_int_equal(binding.desired_revision, 9);
    assert_int_equal(binding.applied_revision, 0);
    assert_int_equal(binding.projection_state,
                     PROVIDER_EFFECTIVE_POLICY_PROJECTION_PENDING);
}

static void
test_effective_policy_binding_generation_is_monotonic(void **state)
{
    struct effective_policy_fixture *fixture = *state;
    char reason[256];

    assert_int_equal(bind_child(fixture, fingerprint_a, "child-1", "phone", 2),
                     PROVIDER_EFFECTIVE_POLICY_OK);
    assert_int_equal(bind_child(fixture, fingerprint_a, "child-1", "phone", 2),
                     PROVIDER_EFFECTIVE_POLICY_IDEMPOTENT);
    assert_int_equal(bind_child(fixture, fingerprint_a, "child-1", "phone", 1),
                     PROVIDER_EFFECTIVE_POLICY_STALE);
    assert_int_equal(bind_child(fixture, fingerprint_a, "child-1", "phone", 3),
                     PROVIDER_EFFECTIVE_POLICY_CONFLICT);
    assert_int_equal(bind_child(fixture, fingerprint_b, "child-1", "phone", 1),
                     PROVIDER_EFFECTIVE_POLICY_STALE);
    assert_int_equal(bind_child(fixture, fingerprint_b, "child-1", "phone", 2),
                     PROVIDER_EFFECTIVE_POLICY_CONFLICT);
    assert_int_equal(fixture->store.binding_count, 1);

    assert_int_equal(bind_child(fixture, fingerprint_b, "child-1", "phone", 3),
                     PROVIDER_EFFECTIVE_POLICY_OK);
    assert_int_equal(provider_effective_policy_binding_enumerate(
                         &fixture->store, "child-1", true, 0, NULL),
                     2);

    assert_int_equal(provider_effective_policy_unbind_child(
                         &fixture->store, fingerprint_a, reason, sizeof(reason)),
                     PROVIDER_EFFECTIVE_POLICY_OK);
    assert_int_equal(bind_child(fixture, fingerprint_a, "child-1", "phone", 2),
                     PROVIDER_EFFECTIVE_POLICY_STALE);

    struct provider_effective_policy_binding old_binding;
    struct provider_effective_policy_binding new_binding;
    assert_true(provider_effective_policy_binding_status(
        &fixture->store, fingerprint_a, &old_binding));
    assert_true(provider_effective_policy_binding_status(
        &fixture->store, fingerprint_b, &new_binding));
    assert_false(old_binding.active);
    assert_true(new_binding.active);
    assert_int_equal(new_binding.credential_generation, 3);
}

static void
test_effective_policy_retired_generation_survives_reload(void **state)
{
    struct effective_policy_fixture *fixture = *state;
    char reason[256];

    assert_int_equal(bind_child(fixture, fingerprint_a, "child-1", "phone", 1),
                     PROVIDER_EFFECTIVE_POLICY_OK);
    assert_int_equal(provider_effective_policy_unbind_child(
                         &fixture->store, fingerprint_a, reason, sizeof(reason)),
                     PROVIDER_EFFECTIVE_POLICY_OK);
    assert_int_equal(bind_child(fixture, fingerprint_b, "child-1", "phone", 2),
                     PROVIDER_EFFECTIVE_POLICY_OK);
    reload_store(fixture);

    assert_int_equal(bind_child(fixture, fingerprint_a, "child-1", "phone", 1),
                     PROVIDER_EFFECTIVE_POLICY_STALE);
    assert_int_equal(bind_child(fixture, fingerprint_c, "child-1", "phone", 1),
                     PROVIDER_EFFECTIVE_POLICY_STALE);
    assert_int_equal(bind_child(fixture, fingerprint_c, "child-1", "phone", 2),
                     PROVIDER_EFFECTIVE_POLICY_CONFLICT);
    assert_int_equal(bind_child(fixture, fingerprint_c, "child-1", "phone", 3),
                     PROVIDER_EFFECTIVE_POLICY_OK);

    struct provider_effective_policy_binding retired;
    assert_true(provider_effective_policy_binding_status(
        &fixture->store, fingerprint_a, &retired));
    assert_false(retired.active);
    assert_int_equal(provider_effective_policy_binding_enumerate(
                         &fixture->store, "child-1", true, 0, NULL),
                     2);
}

static void
test_effective_policy_load_rejects_duplicate_lineage_generation(void **state)
{
    struct effective_policy_fixture *fixture = *state;
    FILE *fp = fopen(fixture->path, "w");
    assert_non_null(fp);
    assert_true(fprintf(fp, "OPENVPN_EFFECTIVE_POLICY\t1\n") > 0);
    assert_true(fprintf(fp,
                        "BINDING\t%s\tchild-1\tphone\t4\t0\t0\t0\tapplied\n",
                        fingerprint_a)
                > 0);
    assert_true(fprintf(fp,
                        "BINDING\t%s\tchild-1\tphone\t4\t0\t0\t0\tapplied\n",
                        fingerprint_b)
                > 0);
    assert_int_equal(fclose(fp), 0);

    char reason[256];
    assert_int_equal(provider_effective_policy_load(
                         &fixture->store, reason, sizeof(reason)),
                     PROVIDER_EFFECTIVE_POLICY_INVALID);
    assert_non_null(strstr(reason,
                           "duplicate credential generation in child lineage"));
    assert_int_equal(fixture->store.binding_count, 0);
}

static void
test_effective_policy_generation_save_failure_rolls_back_clone(void **state)
{
    struct effective_policy_fixture *fixture = *state;
    assert_int_equal(bind_child(fixture, fingerprint_a, "child-1", "phone", 1),
                     PROVIDER_EFFECTIVE_POLICY_OK);

    char original_path[sizeof(fixture->store.path)];
    assert_true(snprintf(original_path, sizeof(original_path), "%s",
                         fixture->store.path)
                > 0);
    char directory_path[320];
    assert_true(snprintf(directory_path, sizeof(directory_path), "%s/fail-target",
                         fixture->directory)
                > 0);
    assert_int_equal(mkdir(directory_path, 0700), 0);
    assert_true(snprintf(fixture->store.path, sizeof(fixture->store.path), "%s",
                         directory_path)
                > 0);

    assert_int_equal(bind_child(fixture, fingerprint_b, "child-1", "phone", 2),
                     PROVIDER_EFFECTIVE_POLICY_IO_ERROR);
    assert_int_equal(fixture->store.binding_count, 1);
    assert_false(provider_effective_policy_binding_status(
        &fixture->store, fingerprint_b,
        &(struct provider_effective_policy_binding){ 0 }));
    struct provider_effective_policy_binding original;
    assert_true(provider_effective_policy_binding_status(
        &fixture->store, fingerprint_a, &original));
    assert_true(original.active);
    assert_int_equal(original.credential_generation, 1);

    assert_true(snprintf(fixture->store.path, sizeof(fixture->store.path), "%s",
                         original_path)
                > 0);
    assert_int_equal(rmdir(directory_path), 0);
}

static void
test_effective_policy_tracks_partial_projection_results(void **state)
{
    struct effective_policy_fixture *fixture = *state;
    char reason[256];
    assert_int_equal(
        accept_snapshot(fixture, "child-1", 3, digest_a,
                        "saving-jane://policy/child-1/3"),
        PROVIDER_EFFECTIVE_POLICY_OK);
    assert_int_equal(bind_child(fixture, fingerprint_a, "child-1", "phone", 1),
                     PROVIDER_EFFECTIVE_POLICY_OK);
    assert_int_equal(bind_child(fixture, fingerprint_b, "child-1", "tablet", 1),
                     PROVIDER_EFFECTIVE_POLICY_OK);

    struct provider_effective_policy_binding a;
    struct provider_effective_policy_binding b;
    assert_true(provider_effective_policy_binding_status(
        &fixture->store, fingerprint_a, &a));
    assert_true(provider_effective_policy_binding_status(
        &fixture->store, fingerprint_b, &b));
    assert_int_equal(a.projection_state,
                     PROVIDER_EFFECTIVE_POLICY_PROJECTION_PENDING);
    assert_int_equal(b.projection_state,
                     PROVIDER_EFFECTIVE_POLICY_PROJECTION_PENDING);

    assert_int_equal(provider_effective_policy_mark_projection_applied(
                         &fixture->store, fingerprint_a, 3, reason,
                         sizeof(reason)),
                     PROVIDER_EFFECTIVE_POLICY_OK);

    assert_true(provider_effective_policy_binding_status(
        &fixture->store, fingerprint_a, &a));
    assert_true(provider_effective_policy_binding_status(
        &fixture->store, fingerprint_b, &b));
    assert_int_equal(a.projection_state,
                     PROVIDER_EFFECTIVE_POLICY_PROJECTION_APPLIED);
    assert_int_equal(b.projection_state,
                     PROVIDER_EFFECTIVE_POLICY_PROJECTION_PENDING);

    assert_int_equal(provider_effective_policy_mark_projection_error(
                         &fixture->store, fingerprint_b, 3, reason,
                         sizeof(reason)),
                     PROVIDER_EFFECTIVE_POLICY_OK);

    assert_true(provider_effective_policy_binding_status(
        &fixture->store, fingerprint_a, &a));
    assert_true(provider_effective_policy_binding_status(
        &fixture->store, fingerprint_b, &b));
    assert_int_equal(a.applied_revision, 3);
    assert_int_equal(a.projection_state,
                     PROVIDER_EFFECTIVE_POLICY_PROJECTION_APPLIED);
    assert_int_equal(b.applied_revision, 0);
    assert_int_equal(b.projection_state,
                     PROVIDER_EFFECTIVE_POLICY_PROJECTION_ERROR);
    assert_int_equal(provider_effective_policy_mark_projection_applied(
                         &fixture->store, fingerprint_b, 2, reason,
                         sizeof(reason)),
                     PROVIDER_EFFECTIVE_POLICY_STALE);
}

static void
test_effective_policy_load_roundtrip(void **state)
{
    struct effective_policy_fixture *fixture = *state;
    char reason[256];
    assert_int_equal(
        accept_snapshot(fixture, "child-1", 11, digest_a,
                        "saving-jane://policy/child-1/11"),
        PROVIDER_EFFECTIVE_POLICY_OK);
    assert_int_equal(bind_child(fixture, fingerprint_c, "child-1", "laptop", 4),
                     PROVIDER_EFFECTIVE_POLICY_OK);
    assert_int_equal(provider_effective_policy_mark_projection_error(
                         &fixture->store, fingerprint_c, 11, reason,
                         sizeof(reason)),
                     PROVIDER_EFFECTIVE_POLICY_OK);

    struct provider_effective_policy_store loaded;
    assert_int_equal(provider_effective_policy_init(
                         &loaded, fixture->path, reason, sizeof(reason)),
                     PROVIDER_EFFECTIVE_POLICY_OK);
    assert_int_equal(provider_effective_policy_load(
                         &loaded, reason, sizeof(reason)),
                     PROVIDER_EFFECTIVE_POLICY_OK);

    struct provider_effective_policy_snapshot snapshot;
    struct provider_effective_policy_binding binding;
    assert_true(provider_effective_policy_snapshot_status(
        &loaded, "child-1", &snapshot));
    assert_true(provider_effective_policy_binding_status(
        &loaded, fingerprint_c, &binding));
    assert_int_equal(snapshot.source_revision, 11);
    assert_string_equal(snapshot.sha256_digest, digest_a);
    assert_int_equal(binding.credential_generation, 4);
    assert_int_equal(binding.desired_revision, 11);
    assert_int_equal(binding.projection_state,
                     PROVIDER_EFFECTIVE_POLICY_PROJECTION_ERROR);
    assert_int_equal(provider_effective_policy_save(
                         &loaded, reason, sizeof(reason)),
                     PROVIDER_EFFECTIVE_POLICY_OK);
    provider_effective_policy_free(&loaded);
}

static void
test_effective_policy_control_lifecycle_persists_fanout(void **state)
{
    struct effective_policy_fixture *fixture = *state;
    char reason[256];

    assert_int_equal(bind_child(fixture, fingerprint_a, "child-1", "phone", 1),
                     PROVIDER_EFFECTIVE_POLICY_OK);
    assert_int_equal(bind_child(fixture, fingerprint_b, "child-1", "tablet", 1),
                     PROVIDER_EFFECTIVE_POLICY_OK);
    assert_int_equal(bind_child(fixture, fingerprint_c, "child-2", "laptop", 1),
                     PROVIDER_EFFECTIVE_POLICY_OK);
    assert_int_equal(
        accept_snapshot(fixture, "child-1", 1, digest_a,
                        "saving-jane://policy/child-1/1"),
        PROVIDER_EFFECTIVE_POLICY_OK);
    assert_int_equal(provider_effective_policy_mark_projection_applied(
                         &fixture->store, fingerprint_a, 1, reason,
                         sizeof(reason)),
                     PROVIDER_EFFECTIVE_POLICY_OK);
    assert_int_equal(provider_effective_policy_mark_projection_error(
                         &fixture->store, fingerprint_b, 1, reason,
                         sizeof(reason)),
                     PROVIDER_EFFECTIVE_POLICY_OK);

    provider_effective_policy_free(&fixture->store);
    assert_int_equal(provider_effective_policy_init(
                         &fixture->store, fixture->path, reason,
                         sizeof(reason)),
                     PROVIDER_EFFECTIVE_POLICY_OK);
    assert_int_equal(provider_effective_policy_load(
                         &fixture->store, reason, sizeof(reason)),
                     PROVIDER_EFFECTIVE_POLICY_OK);
    assert_int_equal(provider_effective_policy_unbind_child(
                         &fixture->store, fingerprint_b, reason,
                         sizeof(reason)),
                     PROVIDER_EFFECTIVE_POLICY_OK);
    assert_int_equal(
        accept_snapshot(fixture, "child-1", 2, digest_b,
                        "saving-jane://policy/child-1/2"),
        PROVIDER_EFFECTIVE_POLICY_OK);

    struct provider_effective_policy_binding phone;
    struct provider_effective_policy_binding tablet;
    struct provider_effective_policy_binding laptop;
    assert_true(provider_effective_policy_binding_status(
        &fixture->store, fingerprint_a, &phone));
    assert_true(provider_effective_policy_binding_status(
        &fixture->store, fingerprint_b, &tablet));
    assert_true(provider_effective_policy_binding_status(
        &fixture->store, fingerprint_c, &laptop));
    assert_true(phone.active);
    assert_int_equal(phone.desired_revision, 2);
    assert_int_equal(phone.applied_revision, 1);
    assert_int_equal(phone.projection_state,
                     PROVIDER_EFFECTIVE_POLICY_PROJECTION_PENDING);
    assert_false(tablet.active);
    assert_int_equal(tablet.desired_revision, 1);
    assert_int_equal(tablet.projection_state,
                     PROVIDER_EFFECTIVE_POLICY_PROJECTION_ERROR);
    assert_true(laptop.active);
    assert_int_equal(laptop.desired_revision, 0);
    assert_int_equal(laptop.projection_state,
                     PROVIDER_EFFECTIVE_POLICY_PROJECTION_APPLIED);
}

static void
test_effective_policy_durable_failure_preserves_memory(void **state)
{
    const struct effective_policy_fixture *fixture = *state;
    char directory_path[320];
    assert_true(snprintf(directory_path, sizeof(directory_path), "%s/fail-target",
                         fixture->directory)
                > 0);
    assert_int_equal(mkdir(directory_path, 0700), 0);

    struct provider_effective_policy_store failing;
    char reason[256];
    assert_int_equal(provider_effective_policy_init(
                         &failing, directory_path, reason, sizeof(reason)),
                     PROVIDER_EFFECTIVE_POLICY_OK);
    assert_int_equal(provider_effective_policy_accept_snapshot(
                         &failing, "child-1", 1, digest_a,
                         "saving-jane://policy/child-1/1", reason,
                         sizeof(reason)),
                     PROVIDER_EFFECTIVE_POLICY_IO_ERROR);
    assert_int_equal(failing.snapshot_count, 0);
    assert_int_equal(failing.binding_count, 0);
    assert_false(provider_effective_policy_snapshot_status(
        &failing, "child-1",
        &(struct provider_effective_policy_snapshot){ 0 }));

    provider_effective_policy_free(&failing);
    assert_int_equal(rmdir(directory_path), 0);
}

int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_effective_policy_result_names_are_stable),
        cmocka_unit_test_setup_teardown(
            test_effective_policy_accepts_valid_snapshot,
            effective_policy_setup, effective_policy_teardown),
        cmocka_unit_test_setup_teardown(
            test_effective_policy_duplicate_stale_and_conflict,
            effective_policy_setup, effective_policy_teardown),
        cmocka_unit_test_setup_teardown(
            test_effective_policy_rejects_bad_metadata,
            effective_policy_setup, effective_policy_teardown),
        cmocka_unit_test_setup_teardown(
            test_effective_policy_user_fanout_is_isolated,
            effective_policy_setup, effective_policy_teardown),
        cmocka_unit_test_setup_teardown(
            test_effective_policy_unbound_child_is_excluded,
            effective_policy_setup, effective_policy_teardown),
        cmocka_unit_test_setup_teardown(
            test_effective_policy_future_binding_inherits_revision,
            effective_policy_setup, effective_policy_teardown),
        cmocka_unit_test_setup_teardown(
            test_effective_policy_binding_generation_is_monotonic,
            effective_policy_setup, effective_policy_teardown),
        cmocka_unit_test_setup_teardown(
            test_effective_policy_retired_generation_survives_reload,
            effective_policy_setup, effective_policy_teardown),
        cmocka_unit_test_setup_teardown(
            test_effective_policy_load_rejects_duplicate_lineage_generation,
            effective_policy_setup, effective_policy_teardown),
        cmocka_unit_test_setup_teardown(
            test_effective_policy_generation_save_failure_rolls_back_clone,
            effective_policy_setup, effective_policy_teardown),
        cmocka_unit_test_setup_teardown(
            test_effective_policy_tracks_partial_projection_results,
            effective_policy_setup, effective_policy_teardown),
        cmocka_unit_test_setup_teardown(
            test_effective_policy_load_roundtrip,
            effective_policy_setup, effective_policy_teardown),
        cmocka_unit_test_setup_teardown(
            test_effective_policy_control_lifecycle_persists_fanout,
            effective_policy_setup, effective_policy_teardown),
        cmocka_unit_test_setup_teardown(
            test_effective_policy_durable_failure_preserves_memory,
            effective_policy_setup, effective_policy_teardown),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
