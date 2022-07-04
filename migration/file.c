/*
 * QEMU live migration via plain file
 *
 * Copyright Red Hat, Inc. 2022
 *
 * Authors:
 *  Daniel P. Berrange <berrange@redhat.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"
#include "channel.h"
#include "file.h"
#include "migration.h"
#include "monitor/monitor.h"
#include "io/channel-file.h"
#include "trace.h"


void file_start_outgoing_migration(MigrationState *s, const char *filename, Error **errp)
{
    QIOChannelFile *ioc;

    trace_migration_file_outgoing(filename);
    ioc = qio_channel_file_new_path(filename, O_WRONLY|O_CREAT|O_TRUNC, 0600, errp);
    if (!ioc) {
        return;
    }

    qio_channel_set_name(QIO_CHANNEL(ioc), "migration-file-outgoing");
    migration_channel_connect(s, QIO_CHANNEL(ioc), NULL, NULL);
    object_unref(OBJECT(ioc));
}


void file_start_incoming_migration(const char *filename, Error **errp)
{
    QIOChannelFile *ioc;

    trace_migration_file_incoming(filename);
    ioc = qio_channel_file_new_path(filename, O_RDONLY, 0600, errp);
    if (!ioc) {
        return;
    }

    qio_channel_set_name(QIO_CHANNEL(ioc), "migration-file-outgoing");
    migration_channel_process_incoming(QIO_CHANNEL(ioc));
    object_unref(OBJECT(ioc));
}
