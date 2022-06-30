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

#ifndef QEMU_MIGRATION_FILE_H
#define QEMU_MIGRATION_FILE_H

void file_start_incoming_migration(const char *filename, Error **errp);

void file_start_outgoing_migration(MigrationState *s,
                                   const char *filename,
                                   Error **errp);

#endif
