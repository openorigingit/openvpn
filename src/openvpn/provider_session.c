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
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, see <https://www.gnu.org/licenses/>.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif

#include "syshead.h"

#include "provider_session.h"

#include "buffer.h"
#include "otime.h"
#include "status.h"

const char *
provider_session_state_name(enum provider_session_state state)
{
    switch (state)
    {
        case PROVIDER_SESSION_STATE_NEW:
            return "new";

        case PROVIDER_SESSION_STATE_AUTH_PENDING:
            return "auth-pending";

        case PROVIDER_SESSION_STATE_ACTIVE:
            return "active";

        case PROVIDER_SESSION_STATE_DRAINING:
            return "draining";

        case PROVIDER_SESSION_STATE_CLOSED:
            return "closed";

        case PROVIDER_SESSION_STATE_UNDEF:
        default:
            return "unknown";
    }
}

static bool
provider_session_replace_string(char **dst, const char *src)
{
    char *copy = string_alloc(src ? src : "", NULL);
    if (!copy)
    {
        return false;
    }

    free(*dst);
    *dst = copy;
    return true;
}

static void
provider_session_free(struct provider_session *session)
{
    if (!session)
    {
        return;
    }

    free(session->provider_name);
    free(session->principal);
    free(session->credential_fingerprint);
    free(session->cert_serial);
    free(session->cert_issuer);
    free(session->assigned_address);
    free(session->authorized_selectors);
    free(session->helper_state);
    free(session->child_sa_state);
    free(session->disconnect_reason);
    free(session);
}

static struct provider_session *
provider_session_lookup_by_cid_any(struct provider_session_table *table, unsigned long cid)
{
    if (!table || !cid)
    {
        return NULL;
    }

    for (struct provider_session *session = table->head;
         session;
         session = session->next)
    {
        if (session->management_cid == cid)
        {
            return session;
        }
    }

    return NULL;
}

void
provider_session_table_init(struct provider_session_table *table)
{
    ASSERT(table);
    CLEAR(*table);
    table->next_session_id = 1;
    table->next_management_cid = 1;
}

void
provider_session_table_free(struct provider_session_table *table)
{
    if (!table)
    {
        return;
    }

    struct provider_session *session = table->head;
    while (session)
    {
        struct provider_session *next = session->next;
        provider_session_free(session);
        session = next;
    }

    CLEAR(*table);
}

size_t
provider_session_table_count(const struct provider_session_table *table)
{
    return table ? table->n_sessions : 0;
}

struct provider_session *
provider_session_create(struct provider_session_table *table,
                        const struct provider_session_create *create)
{
    if (!table || !create)
    {
        return NULL;
    }

    unsigned long cid = create->management_cid;
    if (cid)
    {
        if (provider_session_lookup_by_cid_any(table, cid))
        {
            return NULL;
        }
    }
    else
    {
        do
        {
            cid = table->next_management_cid++;
        }
        while (provider_session_lookup_by_cid_any(table, cid));
    }

    struct provider_session *session;
    ALLOC_OBJ_CLEAR(session, struct provider_session);

    session->id = create->provider_session_id ? create->provider_session_id
                                              : table->next_session_id++;
    if (session->id >= table->next_session_id)
    {
        table->next_session_id = session->id + 1;
    }

    session->management_cid = cid;
    session->xfrm_lease_id = create->xfrm_lease_id;
    session->policy_revision = create->policy_revision;
    session->address_pool_handle = create->address_pool_handle;
    session->has_address_pool_handle = create->has_address_pool_handle;
    session->created = create->now ? create->now : now;
    session->state = PROVIDER_SESSION_STATE_NEW;

    if (!provider_session_replace_string(&session->provider_name, create->provider_name)
        || !provider_session_replace_string(&session->principal, create->principal)
        || !provider_session_replace_string(&session->credential_fingerprint,
                                            create->credential_fingerprint)
        || !provider_session_replace_string(&session->cert_serial,
                                            create->cert_serial)
        || !provider_session_replace_string(&session->cert_issuer,
                                            create->cert_issuer)
        || !provider_session_replace_string(&session->assigned_address,
                                            create->assigned_address)
        || !provider_session_replace_string(&session->authorized_selectors,
                                            create->authorized_selectors)
        || !provider_session_replace_string(&session->helper_state, "")
        || !provider_session_replace_string(&session->child_sa_state, "")
        || !provider_session_replace_string(&session->disconnect_reason, ""))
    {
        provider_session_free(session);
        return NULL;
    }

    session->next = table->head;
    table->head = session;
    ++table->n_sessions;

    return session;
}

bool
provider_session_update(struct provider_session *session,
                        const struct provider_session_update *update)
{
    if (!session || !update || session->halt)
    {
        return false;
    }

    if (update->state != PROVIDER_SESSION_STATE_UNDEF)
    {
        session->state = update->state;
    }

    if (update->helper_state
        && !provider_session_replace_string(&session->helper_state, update->helper_state))
    {
        return false;
    }

    if (update->child_sa_state
        && !provider_session_replace_string(&session->child_sa_state, update->child_sa_state))
    {
        return false;
    }

    session->bytes_received = update->bytes_received;
    session->bytes_sent = update->bytes_sent;
    session->packets_received = update->packets_received;
    session->packets_sent = update->packets_sent;
    return true;
}

bool
provider_session_set_xfrm_lease(struct provider_session *session,
                                const struct provider_session_xfrm_lease *lease)
{
    if (!session || !lease || session->halt)
    {
        return false;
    }

    if (!lease->lease_id || !lease->provider_session_id || !lease->policy_revision
        || !lease->reqid || !lease->address_family
        || !lease->flags || lease->provider_session_id != session->id
        || lease->reserved)
    {
        return false;
    }
    if (lease->expires && lease->rekey_deadline
        && lease->rekey_deadline > lease->expires)
    {
        return false;
    }

    if ((session->xfrm_lease_id && session->xfrm_lease_id != lease->lease_id)
        || (session->policy_revision
            && session->policy_revision != lease->policy_revision))
    {
        return false;
    }

    session->xfrm_lease = *lease;
    session->has_xfrm_lease = true;
    session->xfrm_lease_id = lease->lease_id;
    session->policy_revision = lease->policy_revision;
    return true;
}

bool
provider_session_get_xfrm_lease(const struct provider_session *session,
                                struct provider_session_xfrm_lease *lease)
{
    if (!session || !lease || !session->has_xfrm_lease)
    {
        return false;
    }

    *lease = session->xfrm_lease;
    return true;
}

struct provider_session *
provider_session_lookup_by_cid(struct provider_session_table *table, unsigned long cid)
{
    struct provider_session *session = provider_session_lookup_by_cid_any(table, cid);
    return session && !session->halt ? session : NULL;
}

struct provider_session *
provider_session_lookup_by_id(struct provider_session_table *table, uint64_t id)
{
    if (!table || !id)
    {
        return NULL;
    }

    for (struct provider_session *session = table->head;
         session;
         session = session->next)
    {
        if (session->id == id && !session->halt)
        {
            return session;
        }
    }

    return NULL;
}

bool
provider_session_kill_by_cid(struct provider_session_table *table,
                             unsigned long cid,
                             const char *reason)
{
    struct provider_session *session = provider_session_lookup_by_cid(table, cid);
    if (!session)
    {
        return false;
    }

    session->halt = true;
    session->state = PROVIDER_SESSION_STATE_CLOSED;
    provider_session_replace_string(&session->disconnect_reason,
                                    reason ? reason : "management kill");
    if (table->n_sessions > 0)
    {
        --table->n_sessions;
    }
    return true;
}

bool
provider_session_delete(struct provider_session_table *table,
                        struct provider_session *target)
{
    if (!table || !target)
    {
        return false;
    }

    for (struct provider_session **session = &table->head;
         *session;
         session = &(*session)->next)
    {
        if (*session == target)
        {
            *session = target->next;
            if (!target->halt && table->n_sessions > 0)
            {
                --table->n_sessions;
            }
            provider_session_free(target);
            return true;
        }
    }

    return false;
}

bool
provider_session_delete_by_cid(struct provider_session_table *table,
                               unsigned long cid)
{
    return provider_session_delete(table, provider_session_lookup_by_cid_any(table, cid));
}

static void
provider_session_print_status_v1(const struct provider_session_table *table,
                                 struct status_output *so)
{
    status_printf(so, "PROVIDER SESSION LIST");
    status_printf(so, "Provider,Management CID,Principal,Credential Fingerprint,"
                  "Assigned Address,Authorized Selectors,Bytes Received,Bytes Sent,"
                  "Connected Since,State,Helper State,Child SA State,"
                  "Policy Revision,XFRM Lease ID");

    for (const struct provider_session *session = table->head;
         session;
         session = session->next)
    {
        if (session->halt)
        {
            continue;
        }

        struct gc_arena gc = gc_new();
        status_printf(so, "%s,%lu,%s,%s,%s,%s," counter_format ","
                      counter_format ",%s,%s,%s,%s,%" PRIu64 ",%" PRIu64,
                      session->provider_name,
                      session->management_cid,
                      session->principal,
                      session->credential_fingerprint,
                      session->assigned_address,
                      session->authorized_selectors,
                      session->bytes_received,
                      session->bytes_sent,
                      time_string(session->created, 0, false, &gc),
                      provider_session_state_name(session->state),
                      session->helper_state,
                      session->child_sa_state,
                      session->policy_revision,
                      session->xfrm_lease_id);
        gc_free(&gc);
    }
}

static void
provider_session_print_status_v2(const struct provider_session_table *table,
                                 struct status_output *so,
                                 int version)
{
    const char sep = (version == 3) ? '\t' : ',';

    status_printf(so, "HEADER%cPROVIDER_SESSION%cProvider%cManagement CID%cPrincipal%c"
                  "Credential Fingerprint%cAssigned Address%cAuthorized Selectors%c"
                  "Bytes Received%cBytes Sent%cConnected Since%cState%c"
                  "Helper State%cChild SA State%cPolicy Revision%cXFRM Lease ID",
                  sep, sep, sep, sep, sep, sep, sep, sep, sep, sep, sep, sep, sep,
                  sep, sep);

    for (const struct provider_session *session = table->head;
         session;
         session = session->next)
    {
        if (session->halt)
        {
            continue;
        }

        struct gc_arena gc = gc_new();
        status_printf(so, "PROVIDER_SESSION%c%s%c%lu%c%s%c%s%c%s%c%s%c"
                      counter_format "%c" counter_format "%c%s%c%s%c%s%c%s%c%"
                      PRIu64 "%c%" PRIu64,
                      sep,
                      session->provider_name,
                      sep,
                      session->management_cid,
                      sep,
                      session->principal,
                      sep,
                      session->credential_fingerprint,
                      sep,
                      session->assigned_address,
                      sep,
                      session->authorized_selectors,
                      sep,
                      session->bytes_received,
                      sep,
                      session->bytes_sent,
                      sep,
                      time_string(session->created, 0, false, &gc),
                      sep,
                      provider_session_state_name(session->state),
                      sep,
                      session->helper_state,
                      sep,
                      session->child_sa_state,
                      sep,
                      session->policy_revision,
                      sep,
                      session->xfrm_lease_id);
        gc_free(&gc);
    }
}

void
provider_session_print_status(const struct provider_session_table *table,
                              struct status_output *so,
                              int version)
{
    if (!table || !so || !table->n_sessions)
    {
        return;
    }

    switch (version)
    {
        case 1:
            provider_session_print_status_v1(table, so);
            break;

        case 2:
        case 3:
            provider_session_print_status_v2(table, so, version);
            break;
    }
}
