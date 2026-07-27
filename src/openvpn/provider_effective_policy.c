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

#include "provider_effective_policy.h"

#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#define strncasecmp _strnicmp
#include <fcntl.h>
#include <io.h>
#include <process.h>
#include <sys/stat.h>
#include <windows.h>
#else
#include <fcntl.h>
#include <strings.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#define PROVIDER_EFFECTIVE_POLICY_FORMAT    "OPENVPN_EFFECTIVE_POLICY\t1"
#define PROVIDER_EFFECTIVE_POLICY_LINE_SIZE 2048

static void
provider_effective_policy_set_reason(char *reason, size_t reason_size,
                                     const char *fmt, ...)
{
    if (!reason || reason_size == 0)
    {
        return;
    }

    va_list arglist;
    va_start(arglist, fmt);
    vsnprintf(reason, reason_size, fmt, arglist);
    va_end(arglist);
}

static bool
provider_effective_policy_copy(char *dst, size_t dst_size, const char *src)
{
    if (!dst || dst_size == 0 || !src)
    {
        return false;
    }

    const int ret = snprintf(dst, dst_size, "%s", src);
    return ret >= 0 && (size_t)ret < dst_size;
}

static bool
provider_effective_policy_id_char(unsigned char ch)
{
    return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z')
           || (ch >= '0' && ch <= '9') || ch == '.' || ch == '_'
           || ch == ':' || ch == '@' || ch == '+' || ch == '-';
}

static bool
provider_effective_policy_object_char(unsigned char ch)
{
    return provider_effective_policy_id_char(ch) || ch == '/' || ch == '?'
           || ch == '=' || ch == '&' || ch == '%' || ch == ',';
}

static bool
provider_effective_policy_token_valid(const char *value, size_t size,
                                      bool object_id)
{
    if (!value || !*value)
    {
        return false;
    }

    const size_t len = strlen(value);
    if (len >= size)
    {
        return false;
    }

    for (const unsigned char *cursor = (const unsigned char *)value; *cursor;
         ++cursor)
    {
        if (object_id ? !provider_effective_policy_object_char(*cursor)
                      : !provider_effective_policy_id_char(*cursor))
        {
            return false;
        }
    }
    return true;
}

static bool
provider_effective_policy_hex_char(unsigned char ch)
{
    return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f')
           || (ch >= 'A' && ch <= 'F');
}

static bool
provider_effective_policy_digest_canonicalize(
    const char *digest, char canonical[PROVIDER_EFFECTIVE_POLICY_SHA256_SIZE])
{
    if (!digest || strlen(digest) != PROVIDER_EFFECTIVE_POLICY_SHA256_SIZE - 1)
    {
        return false;
    }

    for (size_t i = 0; i < PROVIDER_EFFECTIVE_POLICY_SHA256_SIZE - 1; ++i)
    {
        const unsigned char ch = (unsigned char)digest[i];
        if (!provider_effective_policy_hex_char(ch))
        {
            return false;
        }
        canonical[i] = (char)tolower(ch);
    }
    canonical[PROVIDER_EFFECTIVE_POLICY_SHA256_SIZE - 1] = '\0';
    return true;
}

static bool
provider_effective_policy_fingerprint_canonicalize(
    const char *fingerprint,
    char canonical[PROVIDER_EFFECTIVE_POLICY_FINGERPRINT_SIZE])
{
    static const char prefix[] = "sha256:";
    const size_t prefix_len = sizeof(prefix) - 1;
    const size_t digest_len = PROVIDER_EFFECTIVE_POLICY_SHA256_SIZE - 1;

    if (!fingerprint || strlen(fingerprint) != prefix_len + digest_len
        || strncasecmp(fingerprint, prefix, prefix_len) != 0)
    {
        return false;
    }

    memcpy(canonical, prefix, prefix_len);
    for (size_t i = 0; i < digest_len; ++i)
    {
        const unsigned char ch = (unsigned char)fingerprint[prefix_len + i];
        if (!provider_effective_policy_hex_char(ch))
        {
            return false;
        }
        canonical[prefix_len + i] = (char)tolower(ch);
    }
    canonical[prefix_len + digest_len] = '\0';
    return true;
}

static bool
provider_effective_policy_path_valid(const char *path)
{
    if (!path || !*path || strlen(path) >= PROVIDER_EFFECTIVE_POLICY_PATH_SIZE)
    {
        return false;
    }

    for (const unsigned char *cursor = (const unsigned char *)path; *cursor;
         ++cursor)
    {
        if (*cursor < 0x20 || *cursor == 0x7f)
        {
            return false;
        }
    }
    return true;
}

static void
provider_effective_policy_release(struct provider_effective_policy_store *store)
{
    if (!store)
    {
        return;
    }
    free(store->snapshots);
    free(store->bindings);
    memset(store, 0, sizeof(*store));
}

static bool
provider_effective_policy_clone(
    const struct provider_effective_policy_store *source,
    struct provider_effective_policy_store *dest)
{
    memset(dest, 0, sizeof(*dest));
    if (!provider_effective_policy_copy(dest->path, sizeof(dest->path),
                                        source->path))
    {
        return false;
    }

    if (source->snapshot_count > 0)
    {
        dest->snapshots = calloc(source->snapshot_count,
                                 sizeof(*dest->snapshots));
        if (!dest->snapshots)
        {
            provider_effective_policy_release(dest);
            return false;
        }
        memcpy(dest->snapshots, source->snapshots,
               source->snapshot_count * sizeof(*dest->snapshots));
        dest->snapshot_count = source->snapshot_count;
        dest->snapshot_capacity = source->snapshot_count;
    }

    if (source->binding_count > 0)
    {
        dest->bindings = calloc(source->binding_count, sizeof(*dest->bindings));
        if (!dest->bindings)
        {
            provider_effective_policy_release(dest);
            return false;
        }
        memcpy(dest->bindings, source->bindings,
               source->binding_count * sizeof(*dest->bindings));
        dest->binding_count = source->binding_count;
        dest->binding_capacity = source->binding_count;
    }
    return true;
}

static bool
provider_effective_policy_reserve_snapshots(
    struct provider_effective_policy_store *store, size_t required)
{
    if (required <= store->snapshot_capacity)
    {
        return true;
    }

    if (store->snapshot_capacity > SIZE_MAX / 2)
    {
        return false;
    }
    size_t capacity = store->snapshot_capacity ? store->snapshot_capacity * 2 : 4;
    if (capacity < required)
    {
        capacity = required;
    }
    if (capacity > SIZE_MAX / sizeof(*store->snapshots))
    {
        return false;
    }

    void *memory = realloc(store->snapshots,
                           capacity * sizeof(*store->snapshots));
    if (!memory)
    {
        return false;
    }
    store->snapshots = memory;
    store->snapshot_capacity = capacity;
    return true;
}

static bool
provider_effective_policy_reserve_bindings(
    struct provider_effective_policy_store *store, size_t required)
{
    if (required <= store->binding_capacity)
    {
        return true;
    }

    if (store->binding_capacity > SIZE_MAX / 2)
    {
        return false;
    }
    size_t capacity = store->binding_capacity ? store->binding_capacity * 2 : 8;
    if (capacity < required)
    {
        capacity = required;
    }
    if (capacity > SIZE_MAX / sizeof(*store->bindings))
    {
        return false;
    }

    void *memory = realloc(store->bindings,
                           capacity * sizeof(*store->bindings));
    if (!memory)
    {
        return false;
    }
    store->bindings = memory;
    store->binding_capacity = capacity;
    return true;
}

static ptrdiff_t
provider_effective_policy_snapshot_index(
    const struct provider_effective_policy_store *store,
    const char *registered_user_id)
{
    for (size_t i = 0; store && i < store->snapshot_count; ++i)
    {
        if (strcmp(store->snapshots[i].registered_user_id,
                   registered_user_id)
            == 0)
        {
            return (ptrdiff_t)i;
        }
    }
    return -1;
}

static ptrdiff_t
provider_effective_policy_binding_index(
    const struct provider_effective_policy_store *store,
    const char *canonical_fingerprint)
{
    for (size_t i = 0; store && i < store->binding_count; ++i)
    {
        if (strcmp(store->bindings[i].credential_fingerprint,
                   canonical_fingerprint)
            == 0)
        {
            return (ptrdiff_t)i;
        }
    }
    return -1;
}

static bool
provider_effective_policy_binding_lineage_matches(
    const struct provider_effective_policy_binding *binding,
    const char *registered_user_id, const char *device_id)
{
    return binding
           && strcmp(binding->registered_user_id, registered_user_id) == 0
           && strcmp(binding->device_id, device_id) == 0;
}

static bool
provider_effective_policy_parse_u64(const char *value, bool allow_zero,
                                    uint64_t *result)
{
    if (!value || !*value || !result || *value == '+' || *value == '-')
    {
        return false;
    }

    errno = 0;
    char *end = NULL;
    const uintmax_t parsed = strtoumax(value, &end, 10);
    if (errno == ERANGE || end == value || *end != '\0' || parsed > UINT64_MAX
        || (!allow_zero && parsed == 0))
    {
        return false;
    }
    *result = (uint64_t)parsed;
    return true;
}

const char *
provider_effective_policy_result_name(enum provider_effective_policy_result result)
{
    switch (result)
    {
        case PROVIDER_EFFECTIVE_POLICY_OK:
            return "ok";
        case PROVIDER_EFFECTIVE_POLICY_IDEMPOTENT:
            return "idempotent";
        case PROVIDER_EFFECTIVE_POLICY_INVALID:
            return "invalid";
        case PROVIDER_EFFECTIVE_POLICY_NOT_FOUND:
            return "not_found";
        case PROVIDER_EFFECTIVE_POLICY_CONFLICT:
            return "conflict";
        case PROVIDER_EFFECTIVE_POLICY_STALE:
            return "stale";
        case PROVIDER_EFFECTIVE_POLICY_IO_ERROR:
            return "io_error";
        case PROVIDER_EFFECTIVE_POLICY_NO_MEMORY:
            return "no_memory";
        default:
            return "unknown";
    }
}

const char *
provider_effective_policy_projection_state_name(
    enum provider_effective_policy_projection_state state)
{
    switch (state)
    {
        case PROVIDER_EFFECTIVE_POLICY_PROJECTION_PENDING:
            return "pending";
        case PROVIDER_EFFECTIVE_POLICY_PROJECTION_APPLIED:
            return "applied";
        case PROVIDER_EFFECTIVE_POLICY_PROJECTION_ERROR:
            return "error";
        default:
            return "unknown";
    }
}

static bool
provider_effective_policy_projection_state_parse(
    const char *value, enum provider_effective_policy_projection_state *state)
{
    if (strcmp(value, "pending") == 0)
    {
        *state = PROVIDER_EFFECTIVE_POLICY_PROJECTION_PENDING;
        return true;
    }
    if (strcmp(value, "applied") == 0)
    {
        *state = PROVIDER_EFFECTIVE_POLICY_PROJECTION_APPLIED;
        return true;
    }
    if (strcmp(value, "error") == 0)
    {
        *state = PROVIDER_EFFECTIVE_POLICY_PROJECTION_ERROR;
        return true;
    }
    return false;
}

static enum provider_effective_policy_result
provider_effective_policy_validate(
    const struct provider_effective_policy_store *store,
    char *reason,
    size_t reason_size)
{
    if (!store || !provider_effective_policy_path_valid(store->path))
    {
        provider_effective_policy_set_reason(reason, reason_size,
                                             "invalid effective-policy path");
        return PROVIDER_EFFECTIVE_POLICY_INVALID;
    }
    if (store->snapshot_count > store->snapshot_capacity
        || store->binding_count > store->binding_capacity
        || (store->snapshot_count > 0 && !store->snapshots)
        || (store->binding_count > 0 && !store->bindings))
    {
        provider_effective_policy_set_reason(reason, reason_size,
                                             "invalid effective-policy storage");
        return PROVIDER_EFFECTIVE_POLICY_INVALID;
    }

    for (size_t i = 0; i < store->snapshot_count; ++i)
    {
        const struct provider_effective_policy_snapshot *snapshot =
            &store->snapshots[i];
        char digest[PROVIDER_EFFECTIVE_POLICY_SHA256_SIZE];
        if (!provider_effective_policy_token_valid(
                snapshot->registered_user_id,
                sizeof(snapshot->registered_user_id), false)
            || snapshot->source_revision == 0
            || !provider_effective_policy_digest_canonicalize(
                snapshot->sha256_digest, digest)
            || strcmp(digest, snapshot->sha256_digest) != 0
            || !provider_effective_policy_token_valid(
                snapshot->object_id, sizeof(snapshot->object_id), true))
        {
            provider_effective_policy_set_reason(
                reason, reason_size, "invalid effective-policy snapshot");
            return PROVIDER_EFFECTIVE_POLICY_INVALID;
        }
        for (size_t j = i + 1; j < store->snapshot_count; ++j)
        {
            if (strcmp(snapshot->registered_user_id,
                       store->snapshots[j].registered_user_id)
                == 0)
            {
                provider_effective_policy_set_reason(
                    reason, reason_size,
                    "duplicate registered-user snapshot");
                return PROVIDER_EFFECTIVE_POLICY_INVALID;
            }
        }
    }

    for (size_t i = 0; i < store->binding_count; ++i)
    {
        const struct provider_effective_policy_binding *binding =
            &store->bindings[i];
        char fingerprint[PROVIDER_EFFECTIVE_POLICY_FINGERPRINT_SIZE];
        if (!provider_effective_policy_fingerprint_canonicalize(
                binding->credential_fingerprint, fingerprint)
            || strcmp(fingerprint, binding->credential_fingerprint) != 0
            || !provider_effective_policy_token_valid(
                binding->registered_user_id,
                sizeof(binding->registered_user_id), false)
            || !provider_effective_policy_token_valid(
                binding->device_id, sizeof(binding->device_id), false)
            || binding->credential_generation == 0
            || binding->applied_revision > binding->desired_revision)
        {
            provider_effective_policy_set_reason(
                reason, reason_size, "invalid effective-policy binding");
            return PROVIDER_EFFECTIVE_POLICY_INVALID;
        }

        if (binding->projection_state
                != PROVIDER_EFFECTIVE_POLICY_PROJECTION_PENDING
            && binding->projection_state
                   != PROVIDER_EFFECTIVE_POLICY_PROJECTION_APPLIED
            && binding->projection_state
                   != PROVIDER_EFFECTIVE_POLICY_PROJECTION_ERROR)
        {
            provider_effective_policy_set_reason(
                reason, reason_size, "invalid binding projection state");
            return PROVIDER_EFFECTIVE_POLICY_INVALID;
        }

        if ((binding->projection_state
                 == PROVIDER_EFFECTIVE_POLICY_PROJECTION_APPLIED
             && binding->applied_revision != binding->desired_revision)
            || ((binding->projection_state
                     == PROVIDER_EFFECTIVE_POLICY_PROJECTION_PENDING
                 || binding->projection_state
                        == PROVIDER_EFFECTIVE_POLICY_PROJECTION_ERROR)
                && binding->applied_revision >= binding->desired_revision))
        {
            provider_effective_policy_set_reason(
                reason, reason_size,
                "binding projection state does not match its revisions");
            return PROVIDER_EFFECTIVE_POLICY_INVALID;
        }

        const ptrdiff_t snapshot_index = provider_effective_policy_snapshot_index(
            store, binding->registered_user_id);
        if (snapshot_index < 0)
        {
            if (binding->desired_revision != 0)
            {
                provider_effective_policy_set_reason(
                    reason, reason_size,
                    "binding references a missing user policy revision");
                return PROVIDER_EFFECTIVE_POLICY_INVALID;
            }
        }
        else
        {
            const uint64_t current =
                store->snapshots[snapshot_index].source_revision;
            if (binding->desired_revision > current
                || (binding->active && binding->desired_revision != current))
            {
                provider_effective_policy_set_reason(
                    reason, reason_size,
                    "binding desired revision is not the current user revision");
                return PROVIDER_EFFECTIVE_POLICY_INVALID;
            }
        }

        for (size_t j = i + 1; j < store->binding_count; ++j)
        {
            const struct provider_effective_policy_binding *other =
                &store->bindings[j];
            if (strcmp(binding->credential_fingerprint,
                       other->credential_fingerprint)
                == 0)
            {
                provider_effective_policy_set_reason(
                    reason, reason_size, "duplicate child binding");
                return PROVIDER_EFFECTIVE_POLICY_INVALID;
            }
            if (provider_effective_policy_binding_lineage_matches(
                    other, binding->registered_user_id, binding->device_id)
                && binding->credential_generation
                       == other->credential_generation)
            {
                provider_effective_policy_set_reason(
                    reason, reason_size,
                    "duplicate credential generation in child lineage");
                return PROVIDER_EFFECTIVE_POLICY_INVALID;
            }
        }
    }

    provider_effective_policy_set_reason(reason, reason_size, "");
    return PROVIDER_EFFECTIVE_POLICY_OK;
}

static int
provider_effective_policy_snapshot_compare(const void *left, const void *right)
{
    const struct provider_effective_policy_snapshot *const *a = left;
    const struct provider_effective_policy_snapshot *const *b = right;
    return strcmp((*a)->registered_user_id, (*b)->registered_user_id);
}

static int
provider_effective_policy_binding_compare(const void *left, const void *right)
{
    const struct provider_effective_policy_binding *const *a = left;
    const struct provider_effective_policy_binding *const *b = right;
    return strcmp((*a)->credential_fingerprint,
                  (*b)->credential_fingerprint);
}

static int
provider_effective_policy_sync_fd(int fd)
{
#ifdef _WIN32
    return _commit(fd);
#else
    return fsync(fd);
#endif
}

static int
provider_effective_policy_temp_open(const char *path, char *temp_path,
                                    size_t temp_path_size)
{
#ifdef _WIN32
    static unsigned long sequence;
    for (unsigned int attempt = 0; attempt < 32; ++attempt)
    {
        const unsigned long value = ++sequence;
        const int ret = snprintf(temp_path, temp_path_size, "%s.tmp.%lu.%lu",
                                 path, (unsigned long)_getpid(), value);
        if (ret < 0 || (size_t)ret >= temp_path_size)
        {
            errno = ENAMETOOLONG;
            return -1;
        }
        const int fd = _open(temp_path,
                             _O_CREAT | _O_EXCL | _O_WRONLY | _O_BINARY,
                             _S_IREAD | _S_IWRITE);
        if (fd >= 0 || errno != EEXIST)
        {
            return fd;
        }
    }
    errno = EEXIST;
    return -1;
#else
    const int ret = snprintf(temp_path, temp_path_size, "%s.tmp.XXXXXX", path);
    if (ret < 0 || (size_t)ret >= temp_path_size)
    {
        errno = ENAMETOOLONG;
        return -1;
    }
    const int fd = mkstemp(temp_path);
    if (fd >= 0)
    {
        (void)fchmod(fd, S_IRUSR | S_IWUSR);
    }
    return fd;
#endif
}

static void
provider_effective_policy_temp_unlink(const char *path)
{
#ifdef _WIN32
    (void)_unlink(path);
#else
    (void)unlink(path);
#endif
}

static bool
provider_effective_policy_replace(const char *temp_path, const char *path)
{
#ifdef _WIN32
    if (MoveFileExA(temp_path, path,
                    MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)
        == 0)
    {
        errno = EIO;
        return false;
    }
    return true;
#else
    return rename(temp_path, path) == 0;
#endif
}

static enum provider_effective_policy_result
provider_effective_policy_write(
    const struct provider_effective_policy_store *store,
    char *reason,
    size_t reason_size)
{
    enum provider_effective_policy_result result =
        provider_effective_policy_validate(store, reason, reason_size);
    if (result != PROVIDER_EFFECTIVE_POLICY_OK)
    {
        return result;
    }

    const struct provider_effective_policy_snapshot **snapshots = NULL;
    const struct provider_effective_policy_binding **bindings = NULL;
    if (store->snapshot_count > 0)
    {
        snapshots = calloc(store->snapshot_count, sizeof(*snapshots));
        if (!snapshots)
        {
            provider_effective_policy_set_reason(reason, reason_size,
                                                 "out of memory sorting snapshots");
            return PROVIDER_EFFECTIVE_POLICY_NO_MEMORY;
        }
        for (size_t i = 0; i < store->snapshot_count; ++i)
        {
            snapshots[i] = &store->snapshots[i];
        }
        qsort(snapshots, store->snapshot_count, sizeof(*snapshots),
              provider_effective_policy_snapshot_compare);
    }
    if (store->binding_count > 0)
    {
        bindings = calloc(store->binding_count, sizeof(*bindings));
        if (!bindings)
        {
            free(snapshots);
            provider_effective_policy_set_reason(reason, reason_size,
                                                 "out of memory sorting bindings");
            return PROVIDER_EFFECTIVE_POLICY_NO_MEMORY;
        }
        for (size_t i = 0; i < store->binding_count; ++i)
        {
            bindings[i] = &store->bindings[i];
        }
        qsort(bindings, store->binding_count, sizeof(*bindings),
              provider_effective_policy_binding_compare);
    }

    char temp_path[PROVIDER_EFFECTIVE_POLICY_PATH_SIZE + 32];
    const int fd = provider_effective_policy_temp_open(
        store->path, temp_path, sizeof(temp_path));
    if (fd < 0)
    {
        const int saved_errno = errno;
        free(snapshots);
        free(bindings);
        provider_effective_policy_set_reason(
            reason, reason_size, "could not create effective-policy temp file: %s",
            strerror(saved_errno));
        return PROVIDER_EFFECTIVE_POLICY_IO_ERROR;
    }

#ifdef _WIN32
    FILE *fp = _fdopen(fd, "wb");
#else
    FILE *fp = fdopen(fd, "w");
#endif
    if (!fp)
    {
        const int saved_errno = errno;
#ifdef _WIN32
        _close(fd);
#else
        close(fd);
#endif
        provider_effective_policy_temp_unlink(temp_path);
        free(snapshots);
        free(bindings);
        provider_effective_policy_set_reason(
            reason, reason_size, "could not stream effective-policy temp file: %s",
            strerror(saved_errno));
        return PROVIDER_EFFECTIVE_POLICY_IO_ERROR;
    }

    bool write_ok = fprintf(fp, "%s\n", PROVIDER_EFFECTIVE_POLICY_FORMAT) >= 0;
    for (size_t i = 0; write_ok && i < store->snapshot_count; ++i)
    {
        const struct provider_effective_policy_snapshot *snapshot = snapshots[i];
        write_ok = fprintf(fp, "USER\t%s\t%" PRIu64 "\t%s\t%s\n",
                           snapshot->registered_user_id,
                           snapshot->source_revision, snapshot->sha256_digest,
                           snapshot->object_id)
                   >= 0;
    }
    for (size_t i = 0; write_ok && i < store->binding_count; ++i)
    {
        const struct provider_effective_policy_binding *binding = bindings[i];
        write_ok = fprintf(
                       fp,
                       "BINDING\t%s\t%s\t%s\t%" PRIu64
                       "\t%d\t%" PRIu64 "\t%" PRIu64 "\t%s\n",
                       binding->credential_fingerprint,
                       binding->registered_user_id, binding->device_id,
                       binding->credential_generation, binding->active ? 1 : 0,
                       binding->desired_revision, binding->applied_revision,
                       provider_effective_policy_projection_state_name(
                           binding->projection_state))
                   >= 0;
    }
    free(snapshots);
    free(bindings);

    if (!write_ok || fflush(fp) != 0)
    {
        const int saved_errno = errno;
        (void)fclose(fp);
        provider_effective_policy_temp_unlink(temp_path);
        provider_effective_policy_set_reason(
            reason, reason_size, "could not write effective-policy state: %s",
            strerror(saved_errno));
        return PROVIDER_EFFECTIVE_POLICY_IO_ERROR;
    }
    if (provider_effective_policy_sync_fd(fd) != 0)
    {
        const int saved_errno = errno;
        (void)fclose(fp);
        provider_effective_policy_temp_unlink(temp_path);
        provider_effective_policy_set_reason(
            reason, reason_size, "could not sync effective-policy state: %s",
            strerror(saved_errno));
        return PROVIDER_EFFECTIVE_POLICY_IO_ERROR;
    }
    if (fclose(fp) != 0)
    {
        const int saved_errno = errno;
        provider_effective_policy_temp_unlink(temp_path);
        provider_effective_policy_set_reason(
            reason, reason_size, "could not close effective-policy state: %s",
            strerror(saved_errno));
        return PROVIDER_EFFECTIVE_POLICY_IO_ERROR;
    }
    if (!provider_effective_policy_replace(temp_path, store->path))
    {
        const int saved_errno = errno;
        provider_effective_policy_temp_unlink(temp_path);
        provider_effective_policy_set_reason(
            reason, reason_size, "could not replace effective-policy state: %s",
            strerror(saved_errno));
        return PROVIDER_EFFECTIVE_POLICY_IO_ERROR;
    }

    provider_effective_policy_set_reason(reason, reason_size, "");
    return PROVIDER_EFFECTIVE_POLICY_OK;
}

enum provider_effective_policy_result
provider_effective_policy_init(struct provider_effective_policy_store *store,
                               const char *path, char *reason,
                               size_t reason_size)
{
    if (!store || !provider_effective_policy_path_valid(path))
    {
        provider_effective_policy_set_reason(reason, reason_size,
                                             "invalid effective-policy path");
        return PROVIDER_EFFECTIVE_POLICY_INVALID;
    }

    memset(store, 0, sizeof(*store));
    provider_effective_policy_copy(store->path, sizeof(store->path), path);
    provider_effective_policy_set_reason(reason, reason_size, "");
    return PROVIDER_EFFECTIVE_POLICY_OK;
}

void
provider_effective_policy_free(struct provider_effective_policy_store *store)
{
    provider_effective_policy_release(store);
}

enum provider_effective_policy_result
provider_effective_policy_save(
    const struct provider_effective_policy_store *store, char *reason,
    size_t reason_size)
{
    return provider_effective_policy_write(store, reason, reason_size);
}

static size_t
provider_effective_policy_split(char *line, char *fields[], size_t max_fields)
{
    size_t count = 0;
    char *cursor = line;
    while (count < max_fields)
    {
        fields[count++] = cursor;
        char *tab = strchr(cursor, '\t');
        if (!tab)
        {
            return count;
        }
        *tab = '\0';
        cursor = tab + 1;
    }
    return strchr(cursor, '\t') ? max_fields + 1 : count;
}

static bool
provider_effective_policy_finish_line(FILE *fp, char *line, size_t line_size)
{
    size_t len = strlen(line);
    if (len == line_size - 1 && line[len - 1] != '\n' && !feof(fp))
    {
        return false;
    }
    if (len > 0 && line[len - 1] == '\n')
    {
        line[--len] = '\0';
    }
    if (len > 0 && line[len - 1] == '\r')
    {
        line[--len] = '\0';
    }
    return !strchr(line, '\r') && !strchr(line, '\n');
}

static enum provider_effective_policy_result
provider_effective_policy_load_snapshot(
    struct provider_effective_policy_store *store, char *fields[],
    size_t field_count, char *reason, size_t reason_size)
{
    char digest[PROVIDER_EFFECTIVE_POLICY_SHA256_SIZE];
    uint64_t revision = 0;
    if (field_count != 5
        || !provider_effective_policy_token_valid(
            fields[1], PROVIDER_EFFECTIVE_POLICY_USER_ID_SIZE, false)
        || !provider_effective_policy_parse_u64(fields[2], false, &revision)
        || !provider_effective_policy_digest_canonicalize(fields[3], digest)
        || strcmp(fields[3], digest) != 0
        || !provider_effective_policy_token_valid(
            fields[4], PROVIDER_EFFECTIVE_POLICY_OBJECT_ID_SIZE, true)
        || provider_effective_policy_snapshot_index(store, fields[1]) >= 0)
    {
        provider_effective_policy_set_reason(reason, reason_size,
                                             "invalid USER record");
        return PROVIDER_EFFECTIVE_POLICY_INVALID;
    }
    if (!provider_effective_policy_reserve_snapshots(
            store, store->snapshot_count + 1))
    {
        provider_effective_policy_set_reason(reason, reason_size,
                                             "out of memory loading USER record");
        return PROVIDER_EFFECTIVE_POLICY_NO_MEMORY;
    }

    struct provider_effective_policy_snapshot *snapshot =
        &store->snapshots[store->snapshot_count++];
    memset(snapshot, 0, sizeof(*snapshot));
    provider_effective_policy_copy(snapshot->registered_user_id,
                                   sizeof(snapshot->registered_user_id), fields[1]);
    snapshot->source_revision = revision;
    provider_effective_policy_copy(snapshot->sha256_digest,
                                   sizeof(snapshot->sha256_digest), digest);
    provider_effective_policy_copy(snapshot->object_id,
                                   sizeof(snapshot->object_id), fields[4]);
    return PROVIDER_EFFECTIVE_POLICY_OK;
}

static enum provider_effective_policy_result
provider_effective_policy_load_binding(
    struct provider_effective_policy_store *store, char *fields[],
    size_t field_count, char *reason, size_t reason_size)
{
    char fingerprint[PROVIDER_EFFECTIVE_POLICY_FINGERPRINT_SIZE];
    uint64_t generation = 0;
    uint64_t desired = 0;
    uint64_t applied = 0;
    enum provider_effective_policy_projection_state state;
    if (field_count != 9
        || !provider_effective_policy_fingerprint_canonicalize(fields[1],
                                                               fingerprint)
        || strcmp(fields[1], fingerprint) != 0
        || !provider_effective_policy_token_valid(
            fields[2], PROVIDER_EFFECTIVE_POLICY_USER_ID_SIZE, false)
        || !provider_effective_policy_token_valid(
            fields[3], PROVIDER_EFFECTIVE_POLICY_DEVICE_ID_SIZE, false)
        || !provider_effective_policy_parse_u64(fields[4], false, &generation)
        || (strcmp(fields[5], "0") != 0 && strcmp(fields[5], "1") != 0)
        || !provider_effective_policy_parse_u64(fields[6], true, &desired)
        || !provider_effective_policy_parse_u64(fields[7], true, &applied)
        || !provider_effective_policy_projection_state_parse(fields[8], &state)
        || provider_effective_policy_binding_index(store, fingerprint) >= 0)
    {
        provider_effective_policy_set_reason(reason, reason_size,
                                             "invalid BINDING record");
        return PROVIDER_EFFECTIVE_POLICY_INVALID;
    }
    if (!provider_effective_policy_reserve_bindings(
            store, store->binding_count + 1))
    {
        provider_effective_policy_set_reason(
            reason, reason_size, "out of memory loading BINDING record");
        return PROVIDER_EFFECTIVE_POLICY_NO_MEMORY;
    }

    struct provider_effective_policy_binding *binding =
        &store->bindings[store->binding_count++];
    memset(binding, 0, sizeof(*binding));
    provider_effective_policy_copy(binding->credential_fingerprint,
                                   sizeof(binding->credential_fingerprint),
                                   fingerprint);
    provider_effective_policy_copy(binding->registered_user_id,
                                   sizeof(binding->registered_user_id), fields[2]);
    provider_effective_policy_copy(binding->device_id,
                                   sizeof(binding->device_id), fields[3]);
    binding->credential_generation = generation;
    binding->active = strcmp(fields[5], "1") == 0;
    binding->desired_revision = desired;
    binding->applied_revision = applied;
    binding->projection_state = state;
    return PROVIDER_EFFECTIVE_POLICY_OK;
}

enum provider_effective_policy_result
provider_effective_policy_load(struct provider_effective_policy_store *store,
                               char *reason, size_t reason_size)
{
    if (!store || !provider_effective_policy_path_valid(store->path))
    {
        provider_effective_policy_set_reason(reason, reason_size,
                                             "invalid effective-policy store");
        return PROVIDER_EFFECTIVE_POLICY_INVALID;
    }

    struct provider_effective_policy_store candidate;
    memset(&candidate, 0, sizeof(candidate));
    provider_effective_policy_copy(candidate.path, sizeof(candidate.path),
                                   store->path);

    FILE *fp = fopen(store->path, "r");
    if (!fp)
    {
        if (errno == ENOENT)
        {
            struct provider_effective_policy_store old = *store;
            *store = candidate;
            memset(&candidate, 0, sizeof(candidate));
            free(old.snapshots);
            free(old.bindings);
            provider_effective_policy_set_reason(reason, reason_size, "");
            return PROVIDER_EFFECTIVE_POLICY_OK;
        }
        const int saved_errno = errno;
        provider_effective_policy_set_reason(
            reason, reason_size, "could not open effective-policy state: %s",
            strerror(saved_errno));
        return PROVIDER_EFFECTIVE_POLICY_IO_ERROR;
    }

    enum provider_effective_policy_result result =
        PROVIDER_EFFECTIVE_POLICY_OK;
    char line[PROVIDER_EFFECTIVE_POLICY_LINE_SIZE];
    if (!fgets(line, sizeof(line), fp))
    {
        result = PROVIDER_EFFECTIVE_POLICY_INVALID;
        provider_effective_policy_set_reason(reason, reason_size,
                                             "empty effective-policy state");
    }
    else
    {
        if (!provider_effective_policy_finish_line(fp, line, sizeof(line)))
        {
            result = PROVIDER_EFFECTIVE_POLICY_INVALID;
            provider_effective_policy_set_reason(
                reason, reason_size, "effective-policy header is too long");
        }
        else if (strcmp(line, PROVIDER_EFFECTIVE_POLICY_FORMAT) != 0)
        {
            result = PROVIDER_EFFECTIVE_POLICY_INVALID;
            provider_effective_policy_set_reason(
                reason, reason_size, "unsupported effective-policy format");
        }
    }

    while (result == PROVIDER_EFFECTIVE_POLICY_OK
           && fgets(line, sizeof(line), fp))
    {
        if (!provider_effective_policy_finish_line(fp, line, sizeof(line)))
        {
            result = PROVIDER_EFFECTIVE_POLICY_INVALID;
            provider_effective_policy_set_reason(
                reason, reason_size, "effective-policy record is too long");
            break;
        }
        if (!*line)
        {
            result = PROVIDER_EFFECTIVE_POLICY_INVALID;
            provider_effective_policy_set_reason(
                reason, reason_size, "empty effective-policy record");
            break;
        }

        char *fields[10];
        const size_t field_count =
            provider_effective_policy_split(line, fields, 10);
        if (strcmp(fields[0], "USER") == 0)
        {
            result = provider_effective_policy_load_snapshot(
                &candidate, fields, field_count, reason, reason_size);
        }
        else if (strcmp(fields[0], "BINDING") == 0)
        {
            result = provider_effective_policy_load_binding(
                &candidate, fields, field_count, reason, reason_size);
        }
        else
        {
            result = PROVIDER_EFFECTIVE_POLICY_INVALID;
            provider_effective_policy_set_reason(
                reason, reason_size, "unknown effective-policy record");
        }
    }

    if (ferror(fp) && result == PROVIDER_EFFECTIVE_POLICY_OK)
    {
        result = PROVIDER_EFFECTIVE_POLICY_IO_ERROR;
        provider_effective_policy_set_reason(reason, reason_size,
                                             "could not read effective-policy state");
    }
    if (fclose(fp) != 0 && result == PROVIDER_EFFECTIVE_POLICY_OK)
    {
        result = PROVIDER_EFFECTIVE_POLICY_IO_ERROR;
        provider_effective_policy_set_reason(reason, reason_size,
                                             "could not close effective-policy state");
    }
    if (result == PROVIDER_EFFECTIVE_POLICY_OK)
    {
        result = provider_effective_policy_validate(&candidate, reason,
                                                    reason_size);
    }
    if (result != PROVIDER_EFFECTIVE_POLICY_OK)
    {
        provider_effective_policy_release(&candidate);
        return result;
    }

    struct provider_effective_policy_store old = *store;
    *store = candidate;
    memset(&candidate, 0, sizeof(candidate));
    free(old.snapshots);
    free(old.bindings);
    provider_effective_policy_set_reason(reason, reason_size, "");
    return PROVIDER_EFFECTIVE_POLICY_OK;
}

static enum provider_effective_policy_result
provider_effective_policy_commit(
    struct provider_effective_policy_store *store,
    struct provider_effective_policy_store *candidate,
    char *reason,
    size_t reason_size)
{
    const enum provider_effective_policy_result result =
        provider_effective_policy_save(candidate, reason, reason_size);
    if (result != PROVIDER_EFFECTIVE_POLICY_OK)
    {
        provider_effective_policy_release(candidate);
        return result;
    }

    struct provider_effective_policy_store old = *store;
    *store = *candidate;
    memset(candidate, 0, sizeof(*candidate));
    free(old.snapshots);
    free(old.bindings);
    return PROVIDER_EFFECTIVE_POLICY_OK;
}

enum provider_effective_policy_result
provider_effective_policy_accept_snapshot(
    struct provider_effective_policy_store *store,
    const char *registered_user_id, uint64_t source_revision,
    const char *sha256_digest, const char *object_id, char *reason,
    size_t reason_size)
{
    char digest[PROVIDER_EFFECTIVE_POLICY_SHA256_SIZE];
    if (!store
        || !provider_effective_policy_token_valid(
            registered_user_id, PROVIDER_EFFECTIVE_POLICY_USER_ID_SIZE, false)
        || source_revision == 0
        || !provider_effective_policy_digest_canonicalize(sha256_digest, digest)
        || !provider_effective_policy_token_valid(
            object_id, PROVIDER_EFFECTIVE_POLICY_OBJECT_ID_SIZE, true))
    {
        provider_effective_policy_set_reason(reason, reason_size,
                                             "invalid policy snapshot metadata");
        return PROVIDER_EFFECTIVE_POLICY_INVALID;
    }

    const ptrdiff_t existing = provider_effective_policy_snapshot_index(
        store, registered_user_id);
    if (existing >= 0)
    {
        const struct provider_effective_policy_snapshot *snapshot =
            &store->snapshots[existing];
        if (source_revision < snapshot->source_revision)
        {
            provider_effective_policy_set_reason(
                reason, reason_size, "policy snapshot revision is stale");
            return PROVIDER_EFFECTIVE_POLICY_STALE;
        }
        if (source_revision == snapshot->source_revision)
        {
            if (strcmp(digest, snapshot->sha256_digest) != 0)
            {
                provider_effective_policy_set_reason(
                    reason, reason_size,
                    "policy snapshot revision has a conflicting digest");
                return PROVIDER_EFFECTIVE_POLICY_CONFLICT;
            }
            if (strcmp(object_id, snapshot->object_id) != 0)
            {
                provider_effective_policy_set_reason(
                    reason, reason_size,
                    "policy snapshot revision has a conflicting object ID");
                return PROVIDER_EFFECTIVE_POLICY_CONFLICT;
            }
            provider_effective_policy_set_reason(reason, reason_size, "");
            return PROVIDER_EFFECTIVE_POLICY_IDEMPOTENT;
        }
    }

    struct provider_effective_policy_store candidate;
    if (!provider_effective_policy_clone(store, &candidate))
    {
        provider_effective_policy_set_reason(reason, reason_size,
                                             "out of memory cloning policy store");
        return PROVIDER_EFFECTIVE_POLICY_NO_MEMORY;
    }

    ptrdiff_t candidate_index = provider_effective_policy_snapshot_index(
        &candidate, registered_user_id);
    if (candidate_index < 0)
    {
        if (!provider_effective_policy_reserve_snapshots(
                &candidate, candidate.snapshot_count + 1))
        {
            provider_effective_policy_release(&candidate);
            provider_effective_policy_set_reason(
                reason, reason_size, "out of memory adding policy snapshot");
            return PROVIDER_EFFECTIVE_POLICY_NO_MEMORY;
        }
        candidate_index = (ptrdiff_t)candidate.snapshot_count++;
    }

    struct provider_effective_policy_snapshot *snapshot =
        &candidate.snapshots[candidate_index];
    memset(snapshot, 0, sizeof(*snapshot));
    provider_effective_policy_copy(snapshot->registered_user_id,
                                   sizeof(snapshot->registered_user_id),
                                   registered_user_id);
    snapshot->source_revision = source_revision;
    provider_effective_policy_copy(snapshot->sha256_digest,
                                   sizeof(snapshot->sha256_digest), digest);
    provider_effective_policy_copy(snapshot->object_id,
                                   sizeof(snapshot->object_id), object_id);

    for (size_t i = 0; i < candidate.binding_count; ++i)
    {
        struct provider_effective_policy_binding *binding =
            &candidate.bindings[i];
        if (binding->active
            && strcmp(binding->registered_user_id, registered_user_id) == 0)
        {
            binding->desired_revision = source_revision;
            binding->projection_state =
                binding->applied_revision == source_revision
                    ? PROVIDER_EFFECTIVE_POLICY_PROJECTION_APPLIED
                    : PROVIDER_EFFECTIVE_POLICY_PROJECTION_PENDING;
        }
    }
    return provider_effective_policy_commit(store, &candidate, reason,
                                            reason_size);
}

enum provider_effective_policy_result
provider_effective_policy_bind_child(
    struct provider_effective_policy_store *store,
    const char *credential_fingerprint, const char *registered_user_id,
    const char *device_id, uint64_t credential_generation, char *reason,
    size_t reason_size)
{
    char fingerprint[PROVIDER_EFFECTIVE_POLICY_FINGERPRINT_SIZE];
    if (!store
        || !provider_effective_policy_fingerprint_canonicalize(
            credential_fingerprint, fingerprint)
        || !provider_effective_policy_token_valid(
            registered_user_id, PROVIDER_EFFECTIVE_POLICY_USER_ID_SIZE, false)
        || !provider_effective_policy_token_valid(
            device_id, PROVIDER_EFFECTIVE_POLICY_DEVICE_ID_SIZE, false)
        || credential_generation == 0)
    {
        provider_effective_policy_set_reason(reason, reason_size,
                                             "invalid child binding metadata");
        return PROVIDER_EFFECTIVE_POLICY_INVALID;
    }

    const ptrdiff_t existing =
        provider_effective_policy_binding_index(store, fingerprint);
    if (existing >= 0)
    {
        const struct provider_effective_policy_binding *binding =
            &store->bindings[existing];
        if (strcmp(binding->registered_user_id, registered_user_id) != 0
            || strcmp(binding->device_id, device_id) != 0)
        {
            provider_effective_policy_set_reason(
                reason, reason_size,
                "credential fingerprint is bound to different child metadata");
            return PROVIDER_EFFECTIVE_POLICY_CONFLICT;
        }
        if (credential_generation < binding->credential_generation)
        {
            provider_effective_policy_set_reason(
                reason, reason_size,
                "child credential generation is older than its lineage");
            return PROVIDER_EFFECTIVE_POLICY_STALE;
        }
        if (credential_generation > binding->credential_generation)
        {
            provider_effective_policy_set_reason(
                reason, reason_size,
                "credential fingerprint is bound to a different generation");
            return PROVIDER_EFFECTIVE_POLICY_CONFLICT;
        }
        if (binding->active)
        {
            provider_effective_policy_set_reason(reason, reason_size, "");
            return PROVIDER_EFFECTIVE_POLICY_IDEMPOTENT;
        }
        provider_effective_policy_set_reason(
            reason, reason_size,
            "retired child credential binding cannot be reactivated");
        return PROVIDER_EFFECTIVE_POLICY_STALE;
    }

    bool lineage_found = false;
    uint64_t lineage_max_generation = 0;
    for (size_t i = 0; i < store->binding_count; ++i)
    {
        const struct provider_effective_policy_binding *binding =
            &store->bindings[i];
        if (provider_effective_policy_binding_lineage_matches(
                binding, registered_user_id, device_id))
        {
            lineage_found = true;
            if (binding->credential_generation > lineage_max_generation)
            {
                lineage_max_generation = binding->credential_generation;
            }
        }
    }
    if (lineage_found && credential_generation < lineage_max_generation)
    {
        provider_effective_policy_set_reason(
            reason, reason_size,
            "child credential generation is older than its lineage");
        return PROVIDER_EFFECTIVE_POLICY_STALE;
    }
    if (lineage_found && credential_generation == lineage_max_generation)
    {
        provider_effective_policy_set_reason(
            reason, reason_size,
            "child credential generation conflicts with its lineage");
        return PROVIDER_EFFECTIVE_POLICY_CONFLICT;
    }

    struct provider_effective_policy_store candidate;
    if (!provider_effective_policy_clone(store, &candidate))
    {
        provider_effective_policy_set_reason(reason, reason_size,
                                             "out of memory cloning policy store");
        return PROVIDER_EFFECTIVE_POLICY_NO_MEMORY;
    }

    if (!provider_effective_policy_reserve_bindings(
            &candidate, candidate.binding_count + 1))
    {
        provider_effective_policy_release(&candidate);
        provider_effective_policy_set_reason(
            reason, reason_size, "out of memory adding child binding");
        return PROVIDER_EFFECTIVE_POLICY_NO_MEMORY;
    }
    const size_t binding_index = candidate.binding_count++;

    const ptrdiff_t snapshot_index = provider_effective_policy_snapshot_index(
        &candidate, registered_user_id);
    const uint64_t desired = snapshot_index >= 0
                                 ? candidate.snapshots[snapshot_index].source_revision
                                 : 0;
    struct provider_effective_policy_binding *binding =
        &candidate.bindings[binding_index];
    memset(binding, 0, sizeof(*binding));
    provider_effective_policy_copy(binding->credential_fingerprint,
                                   sizeof(binding->credential_fingerprint),
                                   fingerprint);
    provider_effective_policy_copy(binding->registered_user_id,
                                   sizeof(binding->registered_user_id),
                                   registered_user_id);
    provider_effective_policy_copy(binding->device_id,
                                   sizeof(binding->device_id), device_id);
    binding->credential_generation = credential_generation;
    binding->active = true;
    binding->desired_revision = desired;
    binding->projection_state = binding->applied_revision == desired
                                    ? PROVIDER_EFFECTIVE_POLICY_PROJECTION_APPLIED
                                    : PROVIDER_EFFECTIVE_POLICY_PROJECTION_PENDING;
    return provider_effective_policy_commit(store, &candidate, reason,
                                            reason_size);
}

enum provider_effective_policy_result
provider_effective_policy_unbind_child(
    struct provider_effective_policy_store *store,
    const char *credential_fingerprint, char *reason, size_t reason_size)
{
    char fingerprint[PROVIDER_EFFECTIVE_POLICY_FINGERPRINT_SIZE];
    if (!store
        || !provider_effective_policy_fingerprint_canonicalize(
            credential_fingerprint, fingerprint))
    {
        provider_effective_policy_set_reason(reason, reason_size,
                                             "invalid child fingerprint");
        return PROVIDER_EFFECTIVE_POLICY_INVALID;
    }
    const ptrdiff_t index =
        provider_effective_policy_binding_index(store, fingerprint);
    if (index < 0)
    {
        provider_effective_policy_set_reason(reason, reason_size,
                                             "child binding not found");
        return PROVIDER_EFFECTIVE_POLICY_NOT_FOUND;
    }
    if (!store->bindings[index].active)
    {
        provider_effective_policy_set_reason(reason, reason_size, "");
        return PROVIDER_EFFECTIVE_POLICY_IDEMPOTENT;
    }

    struct provider_effective_policy_store candidate;
    if (!provider_effective_policy_clone(store, &candidate))
    {
        provider_effective_policy_set_reason(reason, reason_size,
                                             "out of memory cloning policy store");
        return PROVIDER_EFFECTIVE_POLICY_NO_MEMORY;
    }
    candidate.bindings[index].active = false;
    return provider_effective_policy_commit(store, &candidate, reason,
                                            reason_size);
}

static enum provider_effective_policy_result
provider_effective_policy_mark_projection(
    struct provider_effective_policy_store *store,
    const char *credential_fingerprint, uint64_t source_revision,
    enum provider_effective_policy_projection_state state, char *reason,
    size_t reason_size)
{
    char fingerprint[PROVIDER_EFFECTIVE_POLICY_FINGERPRINT_SIZE];
    if (!store || source_revision == 0
        || !provider_effective_policy_fingerprint_canonicalize(
            credential_fingerprint, fingerprint))
    {
        provider_effective_policy_set_reason(reason, reason_size,
                                             "invalid projection result");
        return PROVIDER_EFFECTIVE_POLICY_INVALID;
    }
    const ptrdiff_t index =
        provider_effective_policy_binding_index(store, fingerprint);
    if (index < 0 || !store->bindings[index].active)
    {
        provider_effective_policy_set_reason(reason, reason_size,
                                             "active child binding not found");
        return PROVIDER_EFFECTIVE_POLICY_NOT_FOUND;
    }

    const struct provider_effective_policy_binding *binding =
        &store->bindings[index];
    if (source_revision < binding->desired_revision)
    {
        provider_effective_policy_set_reason(reason, reason_size,
                                             "projection result is stale");
        return PROVIDER_EFFECTIVE_POLICY_STALE;
    }
    if (source_revision > binding->desired_revision)
    {
        provider_effective_policy_set_reason(
            reason, reason_size, "projection result is ahead of desired policy");
        return PROVIDER_EFFECTIVE_POLICY_CONFLICT;
    }
    if (binding->projection_state == state
        && (state != PROVIDER_EFFECTIVE_POLICY_PROJECTION_APPLIED
            || binding->applied_revision == source_revision))
    {
        provider_effective_policy_set_reason(reason, reason_size, "");
        return PROVIDER_EFFECTIVE_POLICY_IDEMPOTENT;
    }
    if (state == PROVIDER_EFFECTIVE_POLICY_PROJECTION_ERROR
        && binding->projection_state
               == PROVIDER_EFFECTIVE_POLICY_PROJECTION_APPLIED)
    {
        provider_effective_policy_set_reason(
            reason, reason_size, "an applied projection cannot regress to error");
        return PROVIDER_EFFECTIVE_POLICY_CONFLICT;
    }

    struct provider_effective_policy_store candidate;
    if (!provider_effective_policy_clone(store, &candidate))
    {
        provider_effective_policy_set_reason(reason, reason_size,
                                             "out of memory cloning policy store");
        return PROVIDER_EFFECTIVE_POLICY_NO_MEMORY;
    }
    candidate.bindings[index].projection_state = state;
    if (state == PROVIDER_EFFECTIVE_POLICY_PROJECTION_APPLIED)
    {
        candidate.bindings[index].applied_revision = source_revision;
    }
    return provider_effective_policy_commit(store, &candidate, reason,
                                            reason_size);
}

enum provider_effective_policy_result
provider_effective_policy_mark_projection_applied(
    struct provider_effective_policy_store *store,
    const char *credential_fingerprint, uint64_t source_revision, char *reason,
    size_t reason_size)
{
    return provider_effective_policy_mark_projection(
        store, credential_fingerprint, source_revision,
        PROVIDER_EFFECTIVE_POLICY_PROJECTION_APPLIED, reason, reason_size);
}

enum provider_effective_policy_result
provider_effective_policy_mark_projection_error(
    struct provider_effective_policy_store *store,
    const char *credential_fingerprint, uint64_t source_revision, char *reason,
    size_t reason_size)
{
    return provider_effective_policy_mark_projection(
        store, credential_fingerprint, source_revision,
        PROVIDER_EFFECTIVE_POLICY_PROJECTION_ERROR, reason, reason_size);
}

bool
provider_effective_policy_snapshot_status(
    const struct provider_effective_policy_store *store,
    const char *registered_user_id,
    struct provider_effective_policy_snapshot *snapshot)
{
    if (!store || !snapshot
        || !provider_effective_policy_token_valid(
            registered_user_id, PROVIDER_EFFECTIVE_POLICY_USER_ID_SIZE, false))
    {
        return false;
    }
    const ptrdiff_t index = provider_effective_policy_snapshot_index(
        store, registered_user_id);
    if (index < 0)
    {
        return false;
    }
    *snapshot = store->snapshots[index];
    return true;
}

bool
provider_effective_policy_binding_status(
    const struct provider_effective_policy_store *store,
    const char *credential_fingerprint,
    struct provider_effective_policy_binding *binding)
{
    char fingerprint[PROVIDER_EFFECTIVE_POLICY_FINGERPRINT_SIZE];
    if (!store || !binding
        || !provider_effective_policy_fingerprint_canonicalize(
            credential_fingerprint, fingerprint))
    {
        return false;
    }
    const ptrdiff_t index =
        provider_effective_policy_binding_index(store, fingerprint);
    if (index < 0)
    {
        return false;
    }
    *binding = store->bindings[index];
    return true;
}

size_t
provider_effective_policy_binding_enumerate(
    const struct provider_effective_policy_store *store,
    const char *registered_user_id, bool active_only, size_t index,
    struct provider_effective_policy_binding *binding)
{
    if (!store
        || (registered_user_id
            && !provider_effective_policy_token_valid(
                registered_user_id, PROVIDER_EFFECTIVE_POLICY_USER_ID_SIZE,
                false)))
    {
        return 0;
    }

    size_t count = 0;
    for (size_t i = 0; i < store->binding_count; ++i)
    {
        const struct provider_effective_policy_binding *candidate =
            &store->bindings[i];
        if ((registered_user_id
             && strcmp(candidate->registered_user_id, registered_user_id) != 0)
            || (active_only && !candidate->active))
        {
            continue;
        }
        if (count == index && binding)
        {
            *binding = *candidate;
        }
        ++count;
    }
    return count;
}
