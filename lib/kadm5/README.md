# kadm5 and iprop

This directory contains Heimdal's `libkadm5clnt` and `libkadm5srv`
implementations, as well as Heimdal's iprop daemons that implement incremental
propagation.

The `libkadm5srv` and iprop implementations are linked closely via the iprop
log mechanism that logs transactions executed via `libkadm5srv`.

> Note that only [write] transactions executed via `libkadm5srv` appear in the
> iprop log.  Write transactions executed via `libhdb` w/o going through
> `libkadm5srv` will not appear in the iprop log, and therefore `libhdb` must
> not be used directly to write to the HDB -- not without quiescing all iprop
> services and all `libkadm5srv`-using services, then resetting the iprop log
> afterwards.

## `kadm5` -- An API for kadmin-Like Transactions Against KDCs

The `kadm5` API comes from OpenVision via MIT Kerberos, dating back to ~1996.

> Note that the `kadm5` API is not a very friendly API mainly because it's
> meant to make it possible to do specific edits to Kerberos principal records
> in the KDB/HDB, but there are some impedance mismatches with respect to the
> HDB entry schema.

There are two kadm5 libraries, both in Heimdal and in MIT Kerberos:

 - `libkadm5clnt` for clients of remote Kerberos databases,

and

 - `libkadm5srv` for local Kerberos databases (the `srv` is due to the fact
   that it is server programs that would use this library).

## `libkadm5clnt`

The Heimdal `libkadm5clnt` library has two backends:

 - one for talking to Heimdal `kadmind`,

and

 - one for talking to Active Directory (AD) domain controllers (via LDAP and
   the RFC 3244 password / key change protocol)

## `libkadm5srv`

The `libkadm5srv` library is used to HDBs directly.

Because the Heimdal Kerberos database layer (`HDB`, in `lib/hdb`) is itself
pluggable, the `libkadm5srv` library can also talk to remote databases,
specifically via LDAP.

## `iprop` -- Incremental HDB Propagation Services

Heimdal's iprop system is based on a log of transactions that is adjuncted to
the local HDB.

Write transactions executed via `kadm5` functions update the HDB and log in a
two-phase commit manner:

 - acquire exclusive/write locks on both the HDB and the log
 - perform all logical checks on the transaction such that it will not be
   rejected once the commit process begins
 - write the transaction ahead to the iprop log
 - write the transaction ahead to the HDB
 - update the iprop log's "uber record" to mark the transaction committed
 - drop the locks

This allows for crash recovery by rolling forward the iprop log.

The log is a regular file with any number of records, each of which has a
header and a footer so as to allow traversal from the beginning to the end and
vice versa.  The record at offset zero is special, being a "no-op" (`nop`) that
records the start offset at which new transactions should be written -- that is
also the offset at which crash recovery looks for uncommitted transactions.

(There can be more than one uncommitted transaction on systems running
`ipropd-slave` in single-primary mode because that program appends to the log
all incremental records from the upstream then invokes the recovery mechanism
to apply them.)

There are three iprop-related programs in Heimdal:

 - `iprop-log(8)` -- an admin utility for examining iprop logs
 - `ipropd-master` -- a daemon that serves incremental updates and also full
   HDBs
 - `ipropd-slave` -- a client daemon to the `ipropd-master` daemon

In single-primary mode, `ipropd-slave` holds an exclusive lock on the local
iprop log at all times, thus precluding all other `libkadm5srv` write
transactions on the local HDB.

In the upcoming multi-primary system, `ipropd-slave` will maintain two logs
(one for the upstream, and a local one), and will not hold an exclusive lock on
the local log while idle, thus allowing local write transactions.

## `iprop` Theory of operation (single-primary)

In this mode:

 - `ipropd-master` serves the local iprop log to its `ipropd-slave` clients;
 - `ipropd-slave` holds an exclusive lock on the local iprop log at all times,
   thus preventing local write transactions by other applications;
 - `ipropd-slave` applies all incremental updates from its upstream
 - if the upstream rolls its iprop log before the downstream can catch up, then
   a "full propagation" ensues where the upstream sends a full dump of its
   local HDB to the downstream

### `iprop` Log Rollover / Truncation

There is a configurable maximum size for iprop logs.  When this maximum is
reached, the log gets reinitialized with the last 1/4 of the entries in the log
retained.  This allows for incremental propagation to work seamlessly
regardless of how many times the log is rolled _provided_ that downstreams
never fall so far behind that the upstream's log is no longer large enough to
bring the downstream up to date with incremental replication.

If a downstream falls so far behind (e.g., due to a lengthy network partition),
then the upstream will send a full HDB dump to the downstream.

### Split-Brain Operation and Recovery

KDCs should operate normally during network partitions.

Recovery from network partitions is straightforward.  There are two recovery
options:

 - pick up incremental update flows where they left off
 - perform a full propagation of HDBs (see above)

## `iprop` Theory of operation (multi-primary)

Multi-primary mode is engaged by running:

 - `ipropd-master` on every primary KDC,
 - one or more instances of `ipropd-slave` with the `--multi-master`
   command-line option each with a different upstream KDC named on the
   command-line
 - one instance of `ipropd-slave` without the `--multi-master` option on KDCs
   that are not masters, if there are any such KDCs

Each `ipropd-slave` defines a uni-directional "link" in an iprop topology.

There must be a path from every primary KDC to every other primary KDC when the
network is fully available.  All topologies that meet this requirement are
allowed.  E.g., the primaries can be arranged into a ring, into a star, fully
meshed, or into rings/stars/meshes of sub-rings/sub-stars/sub-meshes.

A typical deployment might have one or two primaries per-site, and any number
of secondaries in each site, with links between intra-site primaries and
between sites.

Note that the iprop protocol spoken by `ipropd-master` changes minimally, and
backwards-compatibly to support multi-primary mode:

 - `kadm_delete` records now include an `HDB_entry` just like `kadm_create`,
   `kadm_modify`, and `kadm_rename` records;

and

 - every `HDB_entry` appearing in the iprop log includes an `IPropInfo`
   `HDB_extension` that includes the name of the originating KDC and the set of
   KDCs that have seen the iprop record containing the entry.

The `IPropInfo` is used to prevent infinite looping of iprop records:

 - the `IPropInfo` is updated by `ipropd-slave` to include the local KDC's name
   before writing it into the local iprop log and local HDB;

 - `ipropd-slave` drops records received that already list the local KDC's name
   as having seen that record.

### Conflict Resolution

Conflict resolution is deterministic.

A conflict occurs when:

 - a create is received mode for a principal that exists in the local HDB
 - a modify is received for a principal that doesn't exist in the local HDB
 - a rename is received of a principal that doesn't exist in the local HDB
 - a rename is received of a principal where the new name exists in the local HDB
 - a delete is received for a principal that doesn't exist in the local HDB

As well, most modifies of existing principals are treated as conflicts.

For the purposes of conflict resolution:

 - creates are treated as modifies;
 - renames are treated as deletions of the old name and modifies of the new name;
 - modifies of non-existing principals are treated the same as creates;
 - modifies of existing principals are treated as conflicts.

For modifies, conflict resolution algorithm is as follows:

 - the principal with the highest `kvno` wins;
 - the principal most recently written wins;
 - the name of the origin KDC for a transaction is used as a tie-breaker;
 - sets of long-term keys are merged where that makes sense.

For deletes no conflict resolution is needed -- deletions of a non-existing
principal are simply ignored.

In other words, for creates, modifies, and renames, first `ipropd-slave`
determines if the update should be dropped, then it determines if the
`HDB_entry` should be stored as-is, and if not it decides which of a local or
upstream version should be used as the base for keyset merger, it merges
keysets, then stores the merged `HDB_entry` in the HDB.

If two principals are re-keyed concurrently with different keys and they end up
having the same `kvno`, both sets of keys for the current `kvno` will be
included in the merged entry, but the "winner's" keys will come first and will
be used in preference to the "loser's".  What this means is that if a service
principal is rekeyed concurrently then the principal will have the keys needed
to decrypt all extant tickets.

Changing a user principal's password concurrently on different KDCs but to the
same password should not be a problem.  Changing the user principal's password
concurrently on different KDCs to different passwords should cause one of those
to "win".

In the absense of network partitions, KDCs should all reach the same
steady-state HDB contents except for the `IPropInfo` metadata.

### Split-Brain Operation and Recovery

KDCs should operate normally during network partitions.

Recovery from network partitions is straightforward.  There are two recovery
options:

 - pick up incremental update flows where they left off
 - perform a full merge of HDBs

Full merges happen only when an upstream KDC rolled its iprop log before the
network partition cleared up.

A full merge is the same as a full propagation from the upstream's point of
view, but the downstream treats the upstream's full dump as a set of
incremental updates, merging each record in the same way as during normal
incremental propagation.  Thus local transactions are not lost during a full
merge.

## `iprop` Protocol

TBD.  See `lib/kadm5/ipropd_master.c` and `lib/kadm5/ipropd_slave.c`.

Each message in the iprop protocol is one of:

```
  enum iprop_cmd { I_HAVE = 1,
                   FOR_YOU = 2,
                   TELL_YOU_EVERYTHING = 3,
                   ONE_PRINC = 4,
                   NOW_YOU_HAVE = 5,
                   ARE_YOU_THERE = 6,
                   I_AM_HERE = 7,
                   YOU_HAVE_LAST_VERSION = 8
  };
```

 - `I_HAVE` is sent by the downstream to the upstream to indicate what iprop
   record version it last saw from the upstream.

 - `FOR_YOU` is one response to `I_HAVE`, and contains an incremental update
   from the upstream

 - `YOU_HAVE_LAST_VERSION` is another response to `I_HAVE`, indicating that the
   downstream is up to date with the upstream

 - `TELL_YOU_EVERYTHING` is a full propagation from the upstream, with the full
   propagation being a sequence of `ONE_PRINC` messages ending in a
   `NOW_YOU_HAVE`

 - `ARE_YOU_THERE` is used by the upstream to periodically ping the downstream
   during idle times

 - `I_AM_HERE` is the downstream's response to `ARE_YOU_THERE`

## `iprop` Log Format

The iprop log format is described in detail in `lib/kadm5/log.c`, in a large
block comment at the top:

```
/*
 * This file implements the Heimdal iprop logging facility for Heimdal KDC
 * databases.  The logging protocol is a two-phase protocol.  The APIs exposed
 * by this file are for only for internal use by Heimdal, specifically the
 * iprop programs.
 *
 * The iprop logging facility is orthogonal to the HDB and independent of the
 * HDB's internals.  This works when writes to the HDB happen only through
 * Heimdal, but it does not work in the case of, e.g., LDAP.
 *
 * A log consists of a sequence of records of this form:
 *
 * version number		4 bytes -\
 * time in seconds		4 bytes   +> preamble --+> header
 * operation (enum kadm_ops)	4 bytes -/             /
 * n, length of payload		4 bytes --------------+
 *      PAYLOAD DATA...		n bytes
 * n, length of payload		4 bytes ----------------+> trailer
 * version number		4 bytes ->postamble ---/
 *
 * I.e., records have a header and a trailer so that knowing the offset
 * of an record's start or end one can traverse the log forwards and
 * backwards.
 *
 * The log always starts with a nop record that functions as an uber record.
 * The uber record's payload contains the offset (8 bytes) of the first
 * unconfirmed record (typically EOF), and the version number and timestamp of
 * the preceding last confirmed record:
 *
 * offset of next new record    8 bytes
 * last record time             4 bytes
 * last record version number   4 bytes
 *
 * The two-phase protocol consists in only updating the uber record payload
 * (in-place!) after records have been appended.
 *
 * (Note that entries are identified by the pair of 32-bit numbers, the version
 * and the timestamp.  In principle we have a roll-over problem for both, but
 * the timestamp is unsigned, and we could treat these two as one 64-bit
 * sequence number as long as time is monotonic.)
 *
 * When an iprop slave receives a complete database, it saves that version as
 * the last confirmed version, without writing any other records to the log.
 * We use that version as the basis for requesting further updates.
 *
 * kadm5 write operations are done in this order:
 *
 *  - replay unconfirmed log records
 *  - write (append) and fsync() the log record for the kadm5 update
 *  - update the HDB (which includes fsync() or moral equivalent)
 *  - update the log uber record to mark the log record written as
 *    confirmed (not fsync()ed)
 *
 * This makes it possible and safe to seek to the logical end of the log
 * (that is, the end of the last confirmed record) without traversing
 * the whole log forward from offset zero.  Unconfirmed records (which
 * -currently- should never be more than one) can then be found (and
 * rolled forward) by traversing forward from the logical end of the
 * log.  The trailers make it possible to traverse the log backwards
 * from the logical end.
 *
 * This also makes the log + the HDB a two-phase commit with
 * roll-forward system.
 *
 * HDB entry exists and HDB entry does not exist errors occurring during
 * replay of unconfirmed records are ignored.  This is because the
 * corresponding HDB update might have completed.  But also because a
 * change to add aliases to a principal can fail because we don't check
 * for alias conflicts before going ahead with the write operation.
 *
 * Non-sensical and incomplete log records found during roll-forward are
 * truncated.  A log record is non-sensical if its header and trailer
 * don't match.
 *
 * Recovery (by rolling forward) occurs at the next read or write by a
 * kadm5 API reader (e.g., kadmin), but not by an hdb API reader (e.g.,
 * the KDC).  This means that, e.g., a principal rename could fail in
 * between the store and the delete, and recovery might not take place
 * until the next write operation.
 *
 * The log record payload format for create is:
 *
 * DER-encoded HDB_entry        n bytes
 *
 * The log record payload format for update is:
 *
 * mask                         4 bytes
 * DER-encoded HDB_entry        n-4 bytes
 *
 * The log record payload format for delete is:
 *
 * krb5_store_principal         n bytes
 *
 * The log record payload format for rename is:
 *
 * krb5_store_principal         m bytes (old principal name)
 * DER-encoded HDB_entry        n-m bytes (new record)
 *
 * The log record payload format for nop varies:
 *
 *  - The zeroth record in new logs is a nop with a 16 byte payload:
 *
 *    offset of end of last confirmed record        8 bytes
 *    timestamp of last confirmed record            4 bytes
 *    version number of last confirmed record       4 bytes
 *
 *  - New non-zeroth nop records:
 *
 *    nop type                                      4 bytes
 *
 *  - Old nop records:
 *
 *    version number                                4 bytes
 *    timestamp                                     4 bytes
 *
 * Upon initialization, the log's uber record will have version 1, and
 * will be followed by a nop record with version 2.  The version numbers
 * of additional records will be monotonically increasing.
 *
 * Truncation (kadm5_log_truncate()) takes some N > 0 records from the
 * tail of the log and writes them to the beginning of the log after an
 * uber record whose version will then be one less than the first of
 * those records.
 *
 * On masters the log should never have more than one unconfirmed
 * record, but slaves append all of a master's "diffs" and then call
 * kadm5_log_recover() to recover.
 */
```

### HDB and iprop Log Lock-Taking Order

```
/*
 * HDB and log lock order on the master:
 *
 * 1) open and lock the HDB
 * 2) open and lock the log
 * 3) do something
 * 4) unlock and close the log
 * 5) repeat (2)..(4) if desired
 * 6) unlock and close the HDB
 *
 * The kadmin -l lock command can be used to hold the HDB open and
 * locked for multiple operations.
 *
 * HDB and log lock order on the slave:
 *
 * 1) open and lock the log
 * 2) open and lock the HDB
 * 3) replay entries
 * 4) unlock and close the HDB
 * 5) repeat (2)..(4) until signaled
 * 6) unlock and close the HDB
 *
 * The slave doesn't want to allow other local writers, after all, thus
 * the order is reversed.  This means that using "kadmin -l" on a slave
 * will deadlock with ipropd-slave -- don't do that.
 */
```
