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

#ifndef PROVIDER_EFFECTIVE_POLICY_H
#define PROVIDER_EFFECTIVE_POLICY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define PROVIDER_EFFECTIVE_POLICY_PATH_SIZE        1024
#define PROVIDER_EFFECTIVE_POLICY_USER_ID_SIZE     129
#define PROVIDER_EFFECTIVE_POLICY_DEVICE_ID_SIZE   129
#define PROVIDER_EFFECTIVE_POLICY_OBJECT_ID_SIZE   257
#define PROVIDER_EFFECTIVE_POLICY_FINGERPRINT_SIZE 72
#define PROVIDER_EFFECTIVE_POLICY_SHA256_SIZE      65

enum provider_effective_policy_result
{
    PROVIDER_EFFECTIVE_POLICY_OK = 0,
    PROVIDER_EFFECTIVE_POLICY_IDEMPOTENT,
    PROVIDER_EFFECTIVE_POLICY_INVALID,
    PROVIDER_EFFECTIVE_POLICY_NOT_FOUND,
    PROVIDER_EFFECTIVE_POLICY_CONFLICT,
    PROVIDER_EFFECTIVE_POLICY_STALE,
    PROVIDER_EFFECTIVE_POLICY_IO_ERROR,
    PROVIDER_EFFECTIVE_POLICY_NO_MEMORY,
};

enum provider_effective_policy_projection_state
{
    PROVIDER_EFFECTIVE_POLICY_PROJECTION_PENDING = 0,
    PROVIDER_EFFECTIVE_POLICY_PROJECTION_APPLIED,
    PROVIDER_EFFECTIVE_POLICY_PROJECTION_ERROR,
};

/*
 * This is a metadata reference to the authoritative Saving Jane policy
 * object.  Destination allowlist and denylist contents never enter this
 * store.
 */
struct provider_effective_policy_snapshot
{
    char registered_user_id[PROVIDER_EFFECTIVE_POLICY_USER_ID_SIZE];
    uint64_t source_revision;
    char sha256_digest[PROVIDER_EFFECTIVE_POLICY_SHA256_SIZE];
    char object_id[PROVIDER_EFFECTIVE_POLICY_OBJECT_ID_SIZE];
};

struct provider_effective_policy_binding
{
    char credential_fingerprint[PROVIDER_EFFECTIVE_POLICY_FINGERPRINT_SIZE];
    char registered_user_id[PROVIDER_EFFECTIVE_POLICY_USER_ID_SIZE];
    char device_id[PROVIDER_EFFECTIVE_POLICY_DEVICE_ID_SIZE];
    uint64_t credential_generation;
    bool active;
    uint64_t desired_revision;
    uint64_t applied_revision;
    enum provider_effective_policy_projection_state projection_state;
};

struct provider_effective_policy_store
{
    char path[PROVIDER_EFFECTIVE_POLICY_PATH_SIZE];
    struct provider_effective_policy_snapshot *snapshots;
    size_t snapshot_count;
    size_t snapshot_capacity;
    struct provider_effective_policy_binding *bindings;
    size_t binding_count;
    size_t binding_capacity;
};

const char *provider_effective_policy_result_name(
    enum provider_effective_policy_result result);
const char *provider_effective_policy_projection_state_name(
    enum provider_effective_policy_projection_state state);

enum provider_effective_policy_result provider_effective_policy_init(
    struct provider_effective_policy_store *store,
    const char *path,
    char *reason,
    size_t reason_size);
void provider_effective_policy_free(
    struct provider_effective_policy_store *store);

/* Missing state files load as an empty initialized store. */
enum provider_effective_policy_result provider_effective_policy_load(
    struct provider_effective_policy_store *store,
    char *reason,
    size_t reason_size);
enum provider_effective_policy_result provider_effective_policy_save(
    const struct provider_effective_policy_store *store,
    char *reason,
    size_t reason_size);

enum provider_effective_policy_result
provider_effective_policy_accept_snapshot(
    struct provider_effective_policy_store *store,
    const char *registered_user_id,
    uint64_t source_revision,
    const char *sha256_digest,
    const char *object_id,
    char *reason,
    size_t reason_size);

/*
 * Credential generations are monotonic within a registered-user/device
 * lineage.  A newer generation is added without retiring an older active
 * generation so callers can stage a safe rotation.  Retired fingerprints are
 * durable tombstones and cannot be reactivated by replaying bind_child().
 */
enum provider_effective_policy_result provider_effective_policy_bind_child(
    struct provider_effective_policy_store *store,
    const char *credential_fingerprint,
    const char *registered_user_id,
    const char *device_id,
    uint64_t credential_generation,
    char *reason,
    size_t reason_size);

enum provider_effective_policy_result provider_effective_policy_unbind_child(
    struct provider_effective_policy_store *store,
    const char *credential_fingerprint,
    char *reason,
    size_t reason_size);

enum provider_effective_policy_result
provider_effective_policy_mark_projection_applied(
    struct provider_effective_policy_store *store,
    const char *credential_fingerprint,
    uint64_t source_revision,
    char *reason,
    size_t reason_size);

enum provider_effective_policy_result
provider_effective_policy_mark_projection_error(
    struct provider_effective_policy_store *store,
    const char *credential_fingerprint,
    uint64_t source_revision,
    char *reason,
    size_t reason_size);

bool provider_effective_policy_snapshot_status(
    const struct provider_effective_policy_store *store,
    const char *registered_user_id,
    struct provider_effective_policy_snapshot *snapshot);
bool provider_effective_policy_binding_status(
    const struct provider_effective_policy_store *store,
    const char *credential_fingerprint,
    struct provider_effective_policy_binding *binding);

/*
 * Enumerate bindings in stable store order.  NULL registered_user_id selects
 * all users; active_only excludes bindings retired by unbind_child().  The
 * return value is the number of matching bindings.  If index is in range and
 * binding is non-NULL, that matching binding is copied to binding.
 */
size_t provider_effective_policy_binding_enumerate(
    const struct provider_effective_policy_store *store,
    const char *registered_user_id,
    bool active_only,
    size_t index,
    struct provider_effective_policy_binding *binding);

#endif /* PROVIDER_EFFECTIVE_POLICY_H */
