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

#include "manage.h"
#include "options.h"
#include "plugin.h"
#include "platform.h"
#include "provider_policy.h"
#include "pushlist.h"

#define PROVIDER_POLICY_MAX_PUSH_TOKENS 4
#define PROVIDER_POLICY_STATIC_POLICY_REVISION 1

static const char *
provider_policy_skip_spaces(const char *str)
{
    while (*str == ' ' || *str == '\t')
    {
        ++str;
    }
    return str;
}

static bool
provider_policy_copy_string(char *dst, size_t dst_size, const char *src)
{
    if (!dst || !dst_size || !src)
    {
        return false;
    }

    const int ret = snprintf(dst, dst_size, "%s", src);
    return ret >= 0 && (size_t)ret < dst_size;
}

static int
provider_policy_tokenize(const char *option, char *work, size_t work_size,
                         char *tokens[], size_t max_tokens)
{
    if (!option || !work || !work_size || !tokens || !max_tokens
        || !provider_policy_copy_string(work, work_size, option))
    {
        return -1;
    }

    size_t n_tokens = 0;
    char *saveptr = NULL;
    char *token = strtok_r(work, " \t", &saveptr);
    while (token)
    {
        if (n_tokens >= max_tokens)
        {
            return -1;
        }

        tokens[n_tokens++] = token;
        token = strtok_r(NULL, " \t", &saveptr);
    }

    return (int)n_tokens;
}

static bool
provider_policy_parse_ipv4(const char *str, struct in_addr *addr)
{
    return str && addr && inet_pton(AF_INET, str, addr) == 1;
}

static bool
provider_policy_push_option_noop(char *tokens[], int n_tokens)
{
    if (n_tokens == 2 && strcmp(tokens[0], "route-gateway") == 0)
    {
        struct in_addr gateway;
        return provider_policy_parse_ipv4(tokens[1], &gateway);
    }

    if (n_tokens == 2 && strcmp(tokens[0], "topology") == 0)
    {
        return strcmp(tokens[1], "subnet") == 0
               || strcmp(tokens[1], "net30") == 0
               || strcmp(tokens[1], "p2p") == 0;
    }

    return false;
}

static int
provider_policy_netmask_bits(struct in_addr netmask)
{
    uint32_t mask = ntohl(netmask.s_addr);
    int bits = 0;

    while (mask & 0x80000000u)
    {
        ++bits;
        mask <<= 1;
    }

    return mask == 0 ? bits : -1;
}

static bool
provider_policy_plugin_defined(const struct plugin_list *plugins, int plugin_type)
{
#ifdef ENABLE_PLUGIN
    if (!plugins || !plugins->common)
    {
        return false;
    }

    const unsigned int mask = OPENVPN_PLUGIN_MASK(plugin_type);
    for (int i = 0; i < plugins->common->n; ++i)
    {
        if (plugins->common->plugins[i].plugin_type_mask & mask)
        {
            return true;
        }
    }
#endif
    return false;
}

static void
provider_policy_set_reason(char *reason, size_t reason_size, const char *fmt,
                           ...)
{
    if (!reason || !reason_size)
    {
        return;
    }

    va_list arglist;
    va_start(arglist, fmt);
    vsnprintf(reason, reason_size, fmt, arglist);
    va_end(arglist);
}

static void
provider_policy_set_result(struct provider_policy_preflight *result,
                           enum provider_policy_preflight_status status,
                           const char *reason)
{
    if (!result)
    {
        return;
    }

    result->status = status;
    snprintf(result->reason, sizeof(result->reason), "%s", reason);
}

static void
provider_policy_set_auth_result(struct provider_policy_auth_result *result,
                                enum provider_policy_auth_status status,
                                const char *reason)
{
    if (!result)
    {
        return;
    }

    result->status = status;
    result->policy_revision = 0;
    snprintf(result->reason, sizeof(result->reason), "%s", reason);
}

bool
provider_policy_fingerprint_valid(const char *fingerprint)
{
    if (!fingerprint || !*fingerprint)
    {
        return false;
    }

    const size_t len = strlen(fingerprint);
    if (len >= PROVIDER_POLICY_FINGERPRINT_SIZE)
    {
        return false;
    }

    for (const char *pos = fingerprint; *pos; ++pos)
    {
        const unsigned char ch = (unsigned char)*pos;
        if (ch <= ' ' || ch >= 0x7f)
        {
            return false;
        }
    }
    return true;
}

bool
provider_policy_fingerprint_list_defined(
    const struct provider_policy_fingerprint_list *list)
{
    return list && list->head;
}

bool
provider_policy_fingerprint_list_contains(
    const struct provider_policy_fingerprint_list *list,
    const char *credential_fingerprint)
{
    if (!provider_policy_fingerprint_valid(credential_fingerprint))
    {
        return false;
    }

    for (const struct provider_policy_fingerprint_entry *entry =
             list ? list->head : NULL;
         entry;
         entry = entry->next)
    {
        if (entry->credential_fingerprint
            && strcasecmp(entry->credential_fingerprint,
                          credential_fingerprint) == 0)
        {
            return true;
        }
    }
    return false;
}

bool
provider_policy_fingerprint_list_add(
    struct provider_policy_fingerprint_list *list,
    const char *credential_fingerprint,
    struct gc_arena *gc)
{
    if (!list || !provider_policy_fingerprint_valid(credential_fingerprint))
    {
        return false;
    }

    if (provider_policy_fingerprint_list_contains(list, credential_fingerprint))
    {
        return true;
    }

    struct provider_policy_fingerprint_entry *entry;
    if (gc)
    {
        ALLOC_OBJ_CLEAR_GC(entry, struct provider_policy_fingerprint_entry, gc);
    }
    else
    {
        ALLOC_OBJ_CLEAR(entry, struct provider_policy_fingerprint_entry);
    }
    entry->credential_fingerprint = string_alloc(credential_fingerprint, gc);
    if (!entry->credential_fingerprint)
    {
        if (!gc)
        {
            free(entry);
        }
        return false;
    }

    if (list->tail)
    {
        list->tail->next = entry;
    }
    else
    {
        list->head = entry;
    }
    list->tail = entry;
    ++list->count;
    return true;
}

bool
provider_policy_fingerprint_list_add_runtime(
    struct provider_policy_fingerprint_list *list,
    const char *credential_fingerprint)
{
    return provider_policy_fingerprint_list_add(list, credential_fingerprint,
                                                NULL);
}

void
provider_policy_fingerprint_list_free_runtime(
    struct provider_policy_fingerprint_list *list)
{
    if (!list)
    {
        return;
    }

    struct provider_policy_fingerprint_entry *entry = list->head;
    while (entry)
    {
        struct provider_policy_fingerprint_entry *next = entry->next;
        free((char *)entry->credential_fingerprint);
        free(entry);
        entry = next;
    }
    CLEAR(*list);
}

static char *
provider_policy_trim_revocation_line(char *line)
{
    char *start = line;
    while (*start == ' ' || *start == '\t')
    {
        ++start;
    }

    char *comment = strchr(start, '#');
    if (comment)
    {
        *comment = '\0';
    }

    char *end = start + strlen(start);
    while (end > start
           && (end[-1] == ' ' || end[-1] == '\t' || end[-1] == '\r'
               || end[-1] == '\n'))
    {
        --end;
    }
    *end = '\0';
    return start;
}

bool
provider_policy_fingerprint_list_load_runtime(
    struct provider_policy_fingerprint_list *list,
    const char *path,
    char *reason,
    size_t reason_size,
    size_t *loaded_count)
{
    if (loaded_count)
    {
        *loaded_count = 0;
    }
    provider_policy_set_reason(reason, reason_size, "ok");

    if (!list || !path || !*path)
    {
        provider_policy_set_reason(reason, reason_size,
                                   "missing revocation file path");
        return false;
    }

    FILE *fp = platform_fopen(path, "r");
    if (!fp)
    {
        const int open_errno = errno;
        if (open_errno == ENOENT)
        {
            return true;
        }

        provider_policy_set_reason(reason, reason_size,
                                   "could not open revocation file '%s': %s",
                                   path, strerror(open_errno));
        return false;
    }

    char line[512];
    size_t line_number = 0;
    struct provider_policy_fingerprint_list loaded = { 0 };
    while (fgets(line, sizeof(line), fp))
    {
        ++line_number;
        const size_t len = strlen(line);
        if (len && line[len - 1] != '\n' && !feof(fp))
        {
            provider_policy_set_reason(reason, reason_size,
                                       "revocation file '%s' line %zu is too long",
                                       path, line_number);
            provider_policy_fingerprint_list_free_runtime(&loaded);
            fclose(fp);
            return false;
        }

        const char *fingerprint = provider_policy_trim_revocation_line(line);
        if (!*fingerprint)
        {
            continue;
        }

        if (!provider_policy_fingerprint_valid(fingerprint))
        {
            provider_policy_set_reason(
                reason, reason_size,
                "revocation file '%s' line %zu has invalid fingerprint",
                path, line_number);
            provider_policy_fingerprint_list_free_runtime(&loaded);
            fclose(fp);
            return false;
        }

        if (!provider_policy_fingerprint_list_add_runtime(&loaded,
                                                          fingerprint))
        {
            provider_policy_set_reason(
                reason, reason_size,
                "revocation file '%s' line %zu could not be loaded",
                path, line_number);
            provider_policy_fingerprint_list_free_runtime(&loaded);
            fclose(fp);
            return false;
        }
    }

    if (ferror(fp))
    {
        const int read_errno = errno;
        provider_policy_set_reason(reason, reason_size,
                                   "could not read revocation file '%s': %s",
                                   path, strerror(read_errno));
        provider_policy_fingerprint_list_free_runtime(&loaded);
        fclose(fp);
        return false;
    }

    if (fclose(fp) != 0)
    {
        const int close_errno = errno;
        provider_policy_set_reason(reason, reason_size,
                                   "could not close revocation file '%s': %s",
                                   path, strerror(close_errno));
        provider_policy_fingerprint_list_free_runtime(&loaded);
        return false;
    }

    for (const struct provider_policy_fingerprint_entry *entry = loaded.head;
         entry;
         entry = entry->next)
    {
        const size_t old_count = list->count;
        if (!provider_policy_fingerprint_list_add_runtime(
                list, entry->credential_fingerprint))
        {
            provider_policy_set_reason(
                reason, reason_size,
                "revocation file '%s' entry could not be loaded",
                path);
            provider_policy_fingerprint_list_free_runtime(&loaded);
            return false;
        }
        if (loaded_count && list->count != old_count)
        {
            ++*loaded_count;
        }
    }
    provider_policy_fingerprint_list_free_runtime(&loaded);
    return true;
}

bool
provider_policy_fingerprint_list_append_file(
    const char *path,
    const char *credential_fingerprint,
    char *reason,
    size_t reason_size)
{
    provider_policy_set_reason(reason, reason_size, "ok");
    if (!path || !*path)
    {
        provider_policy_set_reason(reason, reason_size,
                                   "missing revocation file path");
        return false;
    }
    if (!provider_policy_fingerprint_valid(credential_fingerprint))
    {
        provider_policy_set_reason(reason, reason_size,
                                   "invalid provider credential fingerprint");
        return false;
    }

#ifdef _WIN32
    FILE *fp = platform_fopen(path, "a");
    if (!fp)
    {
        const int open_errno = errno;
        provider_policy_set_reason(reason, reason_size,
                                   "could not open revocation file '%s': %s",
                                   path, strerror(open_errno));
        return false;
    }
#else
    int fd = platform_open(path, O_CREAT | O_APPEND | O_WRONLY | O_BINARY,
                           S_IRUSR | S_IWUSR);
    if (fd < 0)
    {
        const int open_errno = errno;
        provider_policy_set_reason(reason, reason_size,
                                   "could not open revocation file '%s': %s",
                                   path, strerror(open_errno));
        return false;
    }

    FILE *fp = fdopen(fd, "a");
    if (!fp)
    {
        const int fdopen_errno = errno;
        close(fd);
        provider_policy_set_reason(reason, reason_size,
                                   "could not stream revocation file '%s': %s",
                                   path, strerror(fdopen_errno));
        return false;
    }
#endif

    if (fprintf(fp, "%s\n", credential_fingerprint) < 0 || fflush(fp) != 0)
    {
        const int write_errno = errno;
        fclose(fp);
        provider_policy_set_reason(reason, reason_size,
                                   "could not write revocation file '%s': %s",
                                   path, strerror(write_errno));
        return false;
    }

#ifndef _WIN32
    if (fsync(fd) != 0)
    {
        const int fsync_errno = errno;
        fclose(fp);
        provider_policy_set_reason(reason, reason_size,
                                   "could not sync revocation file '%s': %s",
                                   path, strerror(fsync_errno));
        return false;
    }
#endif

    if (fclose(fp) != 0)
    {
        const int close_errno = errno;
        provider_policy_set_reason(reason, reason_size,
                                   "could not close revocation file '%s': %s",
                                   path, strerror(close_errno));
        return false;
    }
    return true;
}

bool
provider_policy_principal_valid(const char *principal)
{
    if (!principal || !*principal)
    {
        return false;
    }

    const size_t len = strlen(principal);
    if (len >= PROVIDER_POLICY_PRINCIPAL_SIZE)
    {
        return false;
    }

    for (const char *pos = principal; *pos; ++pos)
    {
        const unsigned char ch = (unsigned char)*pos;
        if (ch <= ' ' || ch >= 0x7f)
        {
            return false;
        }
    }
    return true;
}

bool
provider_policy_principal_list_defined(
    const struct provider_policy_principal_list *list)
{
    return list && list->head;
}

bool
provider_policy_principal_list_contains(
    const struct provider_policy_principal_list *list,
    const char *principal)
{
    if (!provider_policy_principal_valid(principal))
    {
        return false;
    }

    for (const struct provider_policy_principal_entry *entry =
             list ? list->head : NULL;
         entry;
         entry = entry->next)
    {
        if (entry->principal && strcmp(entry->principal, principal) == 0)
        {
            return true;
        }
    }
    return false;
}

bool
provider_policy_principal_list_add_runtime(
    struct provider_policy_principal_list *list,
    const char *principal)
{
    if (!list || !provider_policy_principal_valid(principal))
    {
        return false;
    }

    if (provider_policy_principal_list_contains(list, principal))
    {
        return true;
    }

    struct provider_policy_principal_entry *entry;
    ALLOC_OBJ_CLEAR(entry, struct provider_policy_principal_entry);
    entry->principal = string_alloc(principal, NULL);
    if (!entry->principal)
    {
        free(entry);
        return false;
    }

    if (list->tail)
    {
        list->tail->next = entry;
    }
    else
    {
        list->head = entry;
    }
    list->tail = entry;
    ++list->count;
    return true;
}

void
provider_policy_principal_list_free_runtime(
    struct provider_policy_principal_list *list)
{
    if (!list)
    {
        return;
    }

    struct provider_policy_principal_entry *entry = list->head;
    while (entry)
    {
        struct provider_policy_principal_entry *next = entry->next;
        free((char *)entry->principal);
        free(entry);
        entry = next;
    }
    CLEAR(*list);
}

bool
provider_policy_principal_list_load_runtime(
    struct provider_policy_principal_list *list,
    const char *path,
    char *reason,
    size_t reason_size,
    size_t *loaded_count)
{
    if (loaded_count)
    {
        *loaded_count = 0;
    }
    provider_policy_set_reason(reason, reason_size, "ok");

    if (!list || !path || !*path)
    {
        provider_policy_set_reason(reason, reason_size,
                                   "missing principal revocation file path");
        return false;
    }

    FILE *fp = platform_fopen(path, "r");
    if (!fp)
    {
        const int open_errno = errno;
        if (open_errno == ENOENT)
        {
            return true;
        }

        provider_policy_set_reason(
            reason, reason_size,
            "could not open principal revocation file '%s': %s",
            path, strerror(open_errno));
        return false;
    }

    char line[512];
    size_t line_number = 0;
    struct provider_policy_principal_list loaded = { 0 };
    while (fgets(line, sizeof(line), fp))
    {
        ++line_number;
        const size_t len = strlen(line);
        if (len && line[len - 1] != '\n' && !feof(fp))
        {
            provider_policy_set_reason(
                reason, reason_size,
                "principal revocation file '%s' line %zu is too long",
                path, line_number);
            provider_policy_principal_list_free_runtime(&loaded);
            fclose(fp);
            return false;
        }

        const char *principal = provider_policy_trim_revocation_line(line);
        if (!*principal)
        {
            continue;
        }

        if (!provider_policy_principal_valid(principal))
        {
            provider_policy_set_reason(
                reason, reason_size,
                "principal revocation file '%s' line %zu has invalid principal",
                path, line_number);
            provider_policy_principal_list_free_runtime(&loaded);
            fclose(fp);
            return false;
        }

        if (!provider_policy_principal_list_add_runtime(&loaded, principal))
        {
            provider_policy_set_reason(
                reason, reason_size,
                "principal revocation file '%s' line %zu could not be loaded",
                path, line_number);
            provider_policy_principal_list_free_runtime(&loaded);
            fclose(fp);
            return false;
        }
    }

    if (ferror(fp))
    {
        const int read_errno = errno;
        provider_policy_set_reason(
            reason, reason_size,
            "could not read principal revocation file '%s': %s",
            path, strerror(read_errno));
        provider_policy_principal_list_free_runtime(&loaded);
        fclose(fp);
        return false;
    }

    if (fclose(fp) != 0)
    {
        const int close_errno = errno;
        provider_policy_set_reason(
            reason, reason_size,
            "could not close principal revocation file '%s': %s",
            path, strerror(close_errno));
        provider_policy_principal_list_free_runtime(&loaded);
        return false;
    }

    for (const struct provider_policy_principal_entry *entry = loaded.head;
         entry;
         entry = entry->next)
    {
        const size_t old_count = list->count;
        if (!provider_policy_principal_list_add_runtime(list,
                                                        entry->principal))
        {
            provider_policy_set_reason(
                reason, reason_size,
                "principal revocation file '%s' entry could not be loaded",
                path);
            provider_policy_principal_list_free_runtime(&loaded);
            return false;
        }
        if (loaded_count && list->count != old_count)
        {
            ++*loaded_count;
        }
    }
    provider_policy_principal_list_free_runtime(&loaded);
    return true;
}

bool
provider_policy_principal_list_append_file(const char *path,
                                           const char *principal,
                                           char *reason,
                                           size_t reason_size)
{
    provider_policy_set_reason(reason, reason_size, "ok");
    if (!path || !*path)
    {
        provider_policy_set_reason(reason, reason_size,
                                   "missing principal revocation file path");
        return false;
    }
    if (!provider_policy_principal_valid(principal))
    {
        provider_policy_set_reason(reason, reason_size,
                                   "invalid provider principal");
        return false;
    }

#ifdef _WIN32
    FILE *fp = platform_fopen(path, "a");
    if (!fp)
    {
        const int open_errno = errno;
        provider_policy_set_reason(
            reason, reason_size,
            "could not open principal revocation file '%s': %s",
            path, strerror(open_errno));
        return false;
    }
#else
    int fd = platform_open(path, O_CREAT | O_APPEND | O_WRONLY | O_BINARY,
                           S_IRUSR | S_IWUSR);
    if (fd < 0)
    {
        const int open_errno = errno;
        provider_policy_set_reason(
            reason, reason_size,
            "could not open principal revocation file '%s': %s",
            path, strerror(open_errno));
        return false;
    }

    FILE *fp = fdopen(fd, "a");
    if (!fp)
    {
        const int fdopen_errno = errno;
        close(fd);
        provider_policy_set_reason(
            reason, reason_size,
            "could not stream principal revocation file '%s': %s",
            path, strerror(fdopen_errno));
        return false;
    }
#endif

    if (fprintf(fp, "%s\n", principal) < 0 || fflush(fp) != 0)
    {
        const int write_errno = errno;
        fclose(fp);
        provider_policy_set_reason(
            reason, reason_size,
            "could not write principal revocation file '%s': %s",
            path, strerror(write_errno));
        return false;
    }

#ifndef _WIN32
    if (fsync(fd) != 0)
    {
        const int fsync_errno = errno;
        fclose(fp);
        provider_policy_set_reason(
            reason, reason_size,
            "could not sync principal revocation file '%s': %s",
            path, strerror(fsync_errno));
        return false;
    }
#endif

    if (fclose(fp) != 0)
    {
        const int close_errno = errno;
        provider_policy_set_reason(
            reason, reason_size,
            "could not close principal revocation file '%s': %s",
            path, strerror(close_errno));
        return false;
    }
    return true;
}

bool
provider_policy_cert_serial_valid(const char *serial)
{
    if (!serial || !*serial)
    {
        return false;
    }

    const size_t len = strlen(serial);
    if (len >= PROVIDER_POLICY_CERT_SERIAL_SIZE)
    {
        return false;
    }

    for (const char *pos = serial; *pos; ++pos)
    {
        const unsigned char ch = (unsigned char)*pos;
        if (ch <= ' ' || ch >= 0x7f)
        {
            return false;
        }
    }
    return true;
}

bool
provider_policy_cert_issuer_valid(const char *issuer)
{
    if (!issuer || !*issuer)
    {
        return false;
    }

    const size_t len = strlen(issuer);
    if (len >= PROVIDER_POLICY_CERT_ISSUER_SIZE)
    {
        return false;
    }

    for (const char *pos = issuer; *pos; ++pos)
    {
        const unsigned char ch = (unsigned char)*pos;
        if (ch < ' ' || ch >= 0x7f)
        {
            return false;
        }
    }
    return true;
}

bool
provider_policy_cert_list_defined(const struct provider_policy_cert_list *list)
{
    return list && list->head;
}

bool
provider_policy_cert_list_contains(const struct provider_policy_cert_list *list,
                                   const char *serial,
                                   const char *issuer)
{
    if (!provider_policy_cert_serial_valid(serial)
        || !provider_policy_cert_issuer_valid(issuer))
    {
        return false;
    }

    for (const struct provider_policy_cert_entry *entry =
             list ? list->head : NULL;
         entry;
         entry = entry->next)
    {
        if (entry->serial && entry->issuer
            && strcasecmp(entry->serial, serial) == 0
            && strcmp(entry->issuer, issuer) == 0)
        {
            return true;
        }
    }
    return false;
}

bool
provider_policy_cert_list_add_runtime(struct provider_policy_cert_list *list,
                                      const char *serial,
                                      const char *issuer)
{
    if (!list || !provider_policy_cert_serial_valid(serial)
        || !provider_policy_cert_issuer_valid(issuer))
    {
        return false;
    }

    if (provider_policy_cert_list_contains(list, serial, issuer))
    {
        return true;
    }

    struct provider_policy_cert_entry *entry;
    ALLOC_OBJ_CLEAR(entry, struct provider_policy_cert_entry);
    entry->serial = string_alloc(serial, NULL);
    entry->issuer = string_alloc(issuer, NULL);
    if (!entry->serial || !entry->issuer)
    {
        free((char *)entry->serial);
        free((char *)entry->issuer);
        free(entry);
        return false;
    }

    if (list->tail)
    {
        list->tail->next = entry;
    }
    else
    {
        list->head = entry;
    }
    list->tail = entry;
    ++list->count;
    return true;
}

void
provider_policy_cert_list_free_runtime(struct provider_policy_cert_list *list)
{
    if (!list)
    {
        return;
    }

    struct provider_policy_cert_entry *entry = list->head;
    while (entry)
    {
        struct provider_policy_cert_entry *next = entry->next;
        free((char *)entry->serial);
        free((char *)entry->issuer);
        free(entry);
        entry = next;
    }
    CLEAR(*list);
}

static char *
provider_policy_trim_cert_revocation_line(char *line)
{
    char *start = line;
    while (*start == ' ' || *start == '\t')
    {
        ++start;
    }

    if (*start == '#')
    {
        *start = '\0';
        return start;
    }

    char *end = start + strlen(start);
    while (end > start
           && (end[-1] == ' ' || end[-1] == '\t' || end[-1] == '\r'
               || end[-1] == '\n'))
    {
        --end;
    }
    *end = '\0';
    return start;
}

bool
provider_policy_cert_list_load_runtime(struct provider_policy_cert_list *list,
                                       const char *path,
                                       char *reason,
                                       size_t reason_size,
                                       size_t *loaded_count)
{
    if (loaded_count)
    {
        *loaded_count = 0;
    }
    provider_policy_set_reason(reason, reason_size, "ok");

    if (!list || !path || !*path)
    {
        provider_policy_set_reason(reason, reason_size,
                                   "missing certificate revocation file path");
        return false;
    }

    FILE *fp = platform_fopen(path, "r");
    if (!fp)
    {
        const int open_errno = errno;
        if (open_errno == ENOENT)
        {
            return true;
        }

        provider_policy_set_reason(
            reason, reason_size,
            "could not open certificate revocation file '%s': %s",
            path, strerror(open_errno));
        return false;
    }

    char line[1024];
    size_t line_number = 0;
    struct provider_policy_cert_list loaded = { 0 };
    while (fgets(line, sizeof(line), fp))
    {
        ++line_number;
        const size_t len = strlen(line);
        if (len && line[len - 1] != '\n' && !feof(fp))
        {
            provider_policy_set_reason(
                reason, reason_size,
                "certificate revocation file '%s' line %zu is too long",
                path, line_number);
            provider_policy_cert_list_free_runtime(&loaded);
            fclose(fp);
            return false;
        }

        char *entry = provider_policy_trim_cert_revocation_line(line);
        if (!*entry)
        {
            continue;
        }

        char *issuer = strchr(entry, '\t');
        if (!issuer)
        {
            provider_policy_set_reason(
                reason, reason_size,
                "certificate revocation file '%s' line %zu is missing issuer",
                path, line_number);
            provider_policy_cert_list_free_runtime(&loaded);
            fclose(fp);
            return false;
        }
        *issuer++ = '\0';

        if (!provider_policy_cert_serial_valid(entry)
            || !provider_policy_cert_issuer_valid(issuer))
        {
            provider_policy_set_reason(
                reason, reason_size,
                "certificate revocation file '%s' line %zu is invalid",
                path, line_number);
            provider_policy_cert_list_free_runtime(&loaded);
            fclose(fp);
            return false;
        }

        if (!provider_policy_cert_list_add_runtime(&loaded, entry, issuer))
        {
            provider_policy_set_reason(
                reason, reason_size,
                "certificate revocation file '%s' line %zu could not be loaded",
                path, line_number);
            provider_policy_cert_list_free_runtime(&loaded);
            fclose(fp);
            return false;
        }
    }

    if (ferror(fp))
    {
        const int read_errno = errno;
        provider_policy_set_reason(
            reason, reason_size,
            "could not read certificate revocation file '%s': %s",
            path, strerror(read_errno));
        provider_policy_cert_list_free_runtime(&loaded);
        fclose(fp);
        return false;
    }

    if (fclose(fp) != 0)
    {
        const int close_errno = errno;
        provider_policy_set_reason(
            reason, reason_size,
            "could not close certificate revocation file '%s': %s",
            path, strerror(close_errno));
        provider_policy_cert_list_free_runtime(&loaded);
        return false;
    }

    for (const struct provider_policy_cert_entry *cert = loaded.head;
         cert;
         cert = cert->next)
    {
        const size_t old_count = list->count;
        if (!provider_policy_cert_list_add_runtime(list, cert->serial,
                                                   cert->issuer))
        {
            provider_policy_set_reason(
                reason, reason_size,
                "certificate revocation file '%s' entry could not be loaded",
                path);
            provider_policy_cert_list_free_runtime(&loaded);
            return false;
        }
        if (loaded_count && list->count != old_count)
        {
            ++*loaded_count;
        }
    }
    provider_policy_cert_list_free_runtime(&loaded);
    return true;
}

bool
provider_policy_cert_list_append_file(const char *path,
                                      const char *serial,
                                      const char *issuer,
                                      char *reason,
                                      size_t reason_size)
{
    provider_policy_set_reason(reason, reason_size, "ok");
    if (!path || !*path)
    {
        provider_policy_set_reason(reason, reason_size,
                                   "missing certificate revocation file path");
        return false;
    }
    if (!provider_policy_cert_serial_valid(serial)
        || !provider_policy_cert_issuer_valid(issuer))
    {
        provider_policy_set_reason(reason, reason_size,
                                   "invalid provider certificate identity");
        return false;
    }

#ifdef _WIN32
    FILE *fp = platform_fopen(path, "a");
    if (!fp)
    {
        const int open_errno = errno;
        provider_policy_set_reason(
            reason, reason_size,
            "could not open certificate revocation file '%s': %s",
            path, strerror(open_errno));
        return false;
    }
#else
    int fd = platform_open(path, O_CREAT | O_APPEND | O_WRONLY | O_BINARY,
                           S_IRUSR | S_IWUSR);
    if (fd < 0)
    {
        const int open_errno = errno;
        provider_policy_set_reason(
            reason, reason_size,
            "could not open certificate revocation file '%s': %s",
            path, strerror(open_errno));
        return false;
    }

    FILE *fp = fdopen(fd, "a");
    if (!fp)
    {
        const int fdopen_errno = errno;
        close(fd);
        provider_policy_set_reason(
            reason, reason_size,
            "could not stream certificate revocation file '%s': %s",
            path, strerror(fdopen_errno));
        return false;
    }
#endif

    if (fprintf(fp, "%s\t%s\n", serial, issuer) < 0 || fflush(fp) != 0)
    {
        const int write_errno = errno;
        fclose(fp);
        provider_policy_set_reason(
            reason, reason_size,
            "could not write certificate revocation file '%s': %s",
            path, strerror(write_errno));
        return false;
    }

#ifndef _WIN32
    if (fsync(fd) != 0)
    {
        const int fsync_errno = errno;
        fclose(fp);
        provider_policy_set_reason(
            reason, reason_size,
            "could not sync certificate revocation file '%s': %s",
            path, strerror(fsync_errno));
        return false;
    }
#endif

    if (fclose(fp) != 0)
    {
        const int close_errno = errno;
        provider_policy_set_reason(
            reason, reason_size,
            "could not close certificate revocation file '%s': %s",
            path, strerror(close_errno));
        return false;
    }
    return true;
}

const char *
provider_policy_preflight_status_name(enum provider_policy_preflight_status status)
{
    switch (status)
    {
        case PROVIDER_POLICY_PREFLIGHT_OK:
            return "ok";

        case PROVIDER_POLICY_PREFLIGHT_UNSUPPORTED_TLS_VERIFY:
            return "unsupported-tls-verify";

        case PROVIDER_POLICY_PREFLIGHT_UNSUPPORTED_AUTH_USER_PASS:
            return "unsupported-auth-user-pass";

        case PROVIDER_POLICY_PREFLIGHT_UNSUPPORTED_TLS_FINAL:
            return "unsupported-tls-final";

        case PROVIDER_POLICY_PREFLIGHT_UNSUPPORTED_CLIENT_CONNECT:
            return "unsupported-client-connect";

        case PROVIDER_POLICY_PREFLIGHT_UNSUPPORTED_CLIENT_CRRESPONSE:
            return "unsupported-client-crresponse";

        case PROVIDER_POLICY_PREFLIGHT_UNSUPPORTED_MANAGEMENT_AUTH:
            return "unsupported-management-auth";

        case PROVIDER_POLICY_PREFLIGHT_UNSUPPORTED_CCD:
            return "unsupported-ccd";

        case PROVIDER_POLICY_PREFLIGHT_UNSUPPORTED_PUSH_OPTION:
            return "unsupported-push-option";
    }

    return "unknown";
}

void
provider_policy_preflight_init(struct provider_policy_preflight *result)
{
    provider_policy_set_result(result, PROVIDER_POLICY_PREFLIGHT_OK, "ok");
}

void
provider_policy_artifacts_init(struct provider_policy_artifacts *artifacts)
{
    if (artifacts)
    {
        CLEAR(*artifacts);
    }
}

void
provider_policy_auth_result_init(struct provider_policy_auth_result *result)
{
    provider_policy_set_auth_result(result, PROVIDER_POLICY_AUTH_DENIED,
                                    "provider auth not evaluated");
}

bool
provider_policy_push_option_supported(const char *option)
{
    if (!option)
    {
        return false;
    }

    option = provider_policy_skip_spaces(option);
    if (!*option)
    {
        return false;
    }

    char work[OPTION_LINE_SIZE];
    char *tokens[PROVIDER_POLICY_MAX_PUSH_TOKENS];
    const int n_tokens =
        provider_policy_tokenize(option, work, sizeof(work), tokens, SIZE(tokens));
    if (n_tokens <= 0)
    {
        return false;
    }

    /*
     * The MVP translates only policy that has an IKEv2 configuration-payload
     * or traffic-selector equivalent.  OpenVPN-specific PUSH directives must
     * fail closed until the provider path implements them explicitly.
     */
    if (strcmp(tokens[0], "route") == 0)
    {
        struct in_addr network;
        struct in_addr netmask;
        return n_tokens == 3
               && provider_policy_parse_ipv4(tokens[1], &network)
               && provider_policy_parse_ipv4(tokens[2], &netmask)
               && provider_policy_netmask_bits(netmask) >= 0;
    }

    if (strcmp(tokens[0], "dhcp-option") == 0)
    {
        struct in_addr dns;
        return n_tokens == 3
               && strcmp(tokens[1], "DNS") == 0
               && provider_policy_parse_ipv4(tokens[2], &dns);
    }

    if (provider_policy_push_option_noop(tokens, n_tokens))
    {
        return true;
    }

    return false;
}

static bool
provider_policy_reject_push(struct provider_policy_preflight *result,
                            const char *option, const char *why)
{
    if (result)
    {
        result->status = PROVIDER_POLICY_PREFLIGHT_UNSUPPORTED_PUSH_OPTION;
        snprintf(result->reason, sizeof(result->reason),
                 "provider sessions cannot translate PUSH option '%s': %s",
                 option ? option : "(null)", why);
    }
    return false;
}

bool
provider_policy_validate_push_list(const struct push_list *push_list,
                                   struct provider_policy_preflight *result)
{
    struct provider_policy_artifacts artifacts;
    return provider_policy_build_artifacts(push_list, &artifacts, result);
}

static bool
provider_policy_add_route_artifact(const char *option, char *tokens[], int n_tokens,
                                   struct provider_policy_artifacts *artifacts,
                                   struct provider_policy_preflight *result)
{
    if (n_tokens != 3)
    {
        return provider_policy_reject_push(
            result, option, "only 'route <ipv4-network> <ipv4-netmask>' is supported");
    }

    if (artifacts->selector_count >= PROVIDER_POLICY_MAX_SELECTORS)
    {
        return provider_policy_reject_push(result, option, "too many traffic selectors");
    }

    struct in_addr network;
    struct in_addr netmask;
    if (!provider_policy_parse_ipv4(tokens[1], &network)
        || !provider_policy_parse_ipv4(tokens[2], &netmask))
    {
        return provider_policy_reject_push(result, option, "route must use IPv4 literals");
    }

    const int netbits = provider_policy_netmask_bits(netmask);
    if (netbits < 0)
    {
        return provider_policy_reject_push(result, option, "route netmask is not contiguous");
    }

    char network_str[INET_ADDRSTRLEN];
    if (!inet_ntop(AF_INET, &network, network_str, sizeof(network_str)))
    {
        return provider_policy_reject_push(result, option, "route network is invalid");
    }

    char *selector = artifacts->selectors[artifacts->selector_count];
    const int ret = snprintf(selector, PROVIDER_POLICY_SELECTOR_SIZE,
                             "%s/%d", network_str, netbits);
    if (ret < 0 || ret >= PROVIDER_POLICY_SELECTOR_SIZE)
    {
        return provider_policy_reject_push(result, option, "traffic selector is too long");
    }

    ++artifacts->selector_count;
    return true;
}

static bool
provider_policy_add_dns_artifact(const char *option, char *tokens[], int n_tokens,
                                 struct provider_policy_artifacts *artifacts,
                                 struct provider_policy_preflight *result)
{
    if (n_tokens != 3 || strcmp(tokens[1], "DNS") != 0)
    {
        return provider_policy_reject_push(
            result, option, "only 'dhcp-option DNS <ipv4-address>' is supported");
    }

    if (artifacts->dns_server_count >= PROVIDER_POLICY_MAX_DNS_SERVERS)
    {
        return provider_policy_reject_push(result, option, "too many DNS servers");
    }

    struct in_addr dns;
    if (!provider_policy_parse_ipv4(tokens[2], &dns))
    {
        return provider_policy_reject_push(result, option, "DNS server must be an IPv4 literal");
    }

    char dns_str[INET_ADDRSTRLEN];
    if (!inet_ntop(AF_INET, &dns, dns_str, sizeof(dns_str))
        || !provider_policy_copy_string(
            artifacts->dns_servers[artifacts->dns_server_count],
            PROVIDER_POLICY_DNS_SIZE, dns_str))
    {
        return provider_policy_reject_push(result, option, "DNS server is invalid");
    }

    ++artifacts->dns_server_count;
    return true;
}

bool
provider_policy_build_artifacts(const struct push_list *push_list,
                                struct provider_policy_artifacts *artifacts,
                                struct provider_policy_preflight *result)
{
    if (!artifacts)
    {
        provider_policy_reject_push(result, NULL, "artifact output is missing");
        return false;
    }

    provider_policy_artifacts_init(artifacts);
    provider_policy_preflight_init(result);

    if (!push_list)
    {
        return true;
    }

    for (const struct push_entry *entry = push_list->head; entry; entry = entry->next)
    {
        if (!entry->enable)
        {
            continue;
        }

        char work[OPTION_LINE_SIZE];
        char *tokens[PROVIDER_POLICY_MAX_PUSH_TOKENS];
        const int n_tokens =
            provider_policy_tokenize(entry->option, work, sizeof(work),
                                     tokens, SIZE(tokens));
        if (n_tokens <= 0)
        {
            return provider_policy_reject_push(result, entry->option,
                                               "malformed or oversized option");
        }

        if (strcmp(tokens[0], "route") == 0)
        {
            if (!provider_policy_add_route_artifact(entry->option, tokens, n_tokens,
                                                    artifacts, result))
            {
                return false;
            }
        }
        else if (strcmp(tokens[0], "dhcp-option") == 0)
        {
            if (!provider_policy_add_dns_artifact(entry->option, tokens, n_tokens,
                                                  artifacts, result))
            {
                return false;
            }
        }
        else if (provider_policy_push_option_noop(tokens, n_tokens))
        {
            continue;
        }
        else
        {
            return provider_policy_reject_push(result, entry->option,
                                               "unsupported option");
        }
    }

    return true;
}

bool
provider_policy_preflight(const struct options *options,
                          const struct plugin_list *plugins,
                          struct provider_policy_preflight *result)
{
    provider_policy_preflight_init(result);

    if (!options)
    {
        return true;
    }

    if (provider_policy_plugin_defined(plugins, OPENVPN_PLUGIN_TLS_VERIFY))
    {
        provider_policy_set_result(
            result, PROVIDER_POLICY_PREFLIGHT_UNSUPPORTED_TLS_VERIFY,
            "OPENVPN_PLUGIN_TLS_VERIFY is TLS-chain based and has no provider-session mapping");
        return false;
    }

    if (provider_policy_plugin_defined(plugins, OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY)
        || options->auth_user_pass_verify_script)
    {
        provider_policy_set_result(
            result, PROVIDER_POLICY_PREFLIGHT_UNSUPPORTED_AUTH_USER_PASS,
            "username/password auth hooks are not implemented for the EAP-TLS provider MVP");
        return false;
    }

    if (provider_policy_plugin_defined(plugins, OPENVPN_PLUGIN_TLS_FINAL))
    {
        provider_policy_set_result(
            result, PROVIDER_POLICY_PREFLIGHT_UNSUPPORTED_TLS_FINAL,
            "OPENVPN_PLUGIN_TLS_FINAL is TLS-session based and has no provider-session mapping");
        return false;
    }

    if (provider_policy_plugin_defined(plugins, OPENVPN_PLUGIN_CLIENT_CONNECT)
        || provider_policy_plugin_defined(plugins, OPENVPN_PLUGIN_CLIENT_CONNECT_DEFER)
        || provider_policy_plugin_defined(plugins, OPENVPN_PLUGIN_CLIENT_CONNECT_V2)
        || provider_policy_plugin_defined(plugins, OPENVPN_PLUGIN_CLIENT_CONNECT_DEFER_V2)
        || options->client_connect_script)
    {
        provider_policy_set_result(
            result, PROVIDER_POLICY_PREFLIGHT_UNSUPPORTED_CLIENT_CONNECT,
            "client-connect hooks require provider-specific environment and return handling");
        return false;
    }

    if (provider_policy_plugin_defined(plugins, OPENVPN_PLUGIN_CLIENT_CRRESPONSE)
        || options->client_crresponse_script)
    {
        provider_policy_set_result(
            result, PROVIDER_POLICY_PREFLIGHT_UNSUPPORTED_CLIENT_CRRESPONSE,
            "challenge/response hooks are not implemented for provider sessions");
        return false;
    }

    if (MAN_CLIENT_AUTH_ENABLED(options))
    {
        provider_policy_set_result(
            result, PROVIDER_POLICY_PREFLIGHT_UNSUPPORTED_MANAGEMENT_AUTH,
            "--management-client-auth currently keys deferred auth to tls_multi/mda_key_id");
        return false;
    }

    if (options->client_config_dir || options->ccd_exclusive)
    {
        provider_policy_set_result(
            result, PROVIDER_POLICY_PREFLIGHT_UNSUPPORTED_CCD,
            "--client-config-dir requires provider principal lookup and option import support");
        return false;
    }

    return provider_policy_validate_push_list(&options->push_list, result);
}

bool
provider_policy_authorize(const struct provider_policy_auth_context *context,
                          struct provider_policy_auth_result *result)
{
    provider_policy_auth_result_init(result);

    if (!context)
    {
        provider_policy_set_auth_result(result, PROVIDER_POLICY_AUTH_DENIED,
                                        "provider auth context is missing");
        return false;
    }
    if (context->profile_mode != PROVIDER_POLICY_PROFILE_EAP_TLS)
    {
        provider_policy_set_auth_result(result, PROVIDER_POLICY_AUTH_DENIED,
                                        "unsupported provider auth profile");
        return false;
    }
    if (!context->principal || !*context->principal)
    {
        provider_policy_set_auth_result(result, PROVIDER_POLICY_AUTH_DENIED,
                                        "provider principal is missing");
        return false;
    }
    if (provider_policy_principal_list_contains(context->revoked_principals,
                                                context->principal))
    {
        provider_policy_set_auth_result(result, PROVIDER_POLICY_AUTH_DENIED,
                                        "provider principal is revoked");
        return false;
    }
    if (!context->credential_fingerprint || !*context->credential_fingerprint)
    {
        provider_policy_set_auth_result(
            result, PROVIDER_POLICY_AUTH_DENIED,
            "provider credential fingerprint is required");
        return false;
    }
    if (!context->cert_serial || !*context->cert_serial)
    {
        provider_policy_set_auth_result(result, PROVIDER_POLICY_AUTH_DENIED,
                                        "provider certificate serial is required");
        return false;
    }
    if (!context->cert_issuer || !*context->cert_issuer)
    {
        provider_policy_set_auth_result(result, PROVIDER_POLICY_AUTH_DENIED,
                                        "provider certificate issuer is required");
        return false;
    }
    if (provider_policy_cert_list_contains(context->revoked_certs,
                                           context->cert_serial,
                                           context->cert_issuer))
    {
        provider_policy_set_auth_result(
            result, PROVIDER_POLICY_AUTH_DENIED,
            "provider certificate identity is revoked");
        return false;
    }
    if (provider_policy_fingerprint_list_contains(
            context->revoked_fingerprints, context->credential_fingerprint))
    {
        provider_policy_set_auth_result(
            result, PROVIDER_POLICY_AUTH_DENIED,
            "provider credential fingerprint is revoked");
        return false;
    }
    if (!provider_policy_fingerprint_list_contains(
            context->allowed_fingerprints, context->credential_fingerprint))
    {
        provider_policy_set_auth_result(
            result, PROVIDER_POLICY_AUTH_DENIED,
            "provider credential fingerprint is not allowed");
        return false;
    }

    provider_policy_set_auth_result(result, PROVIDER_POLICY_AUTH_AUTHORIZED,
                                    "authorized");
    if (result)
    {
        result->policy_revision = context->policy_revision
                                  ? context->policy_revision
                                  : PROVIDER_POLICY_STATIC_POLICY_REVISION;
    }
    return true;
}
