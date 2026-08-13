"""The three statements that have to be raw SQL, kept together and explained.

Everything else in this package goes through ``ScopedRepository``. These do not,
because each needs something the ORM cannot express:

* ``CLAIM_JOBS`` needs ``FOR UPDATE SKIP LOCKED`` inside a subquery of an UPDATE,
  which is the exact shape docs/AGENT-PROTOCOL.md §3 mandates. Without SKIP
  LOCKED two agents polling at once serialise on the same row and one of them
  gets a job the other already took.
* ``HOSTS_INSIDE_REGISTERED_NETWORKS`` checks a whole batch of submitted
  addresses against the org's networks in one round trip using the native
  ``cidr >>= inet`` operator. The alternative — fetching every network and
  looping in Python — is either unbounded or silently truncated.
* ``CONSUME_ENROLLMENT_TOKEN`` (in ``agents.enrollment``) is the third; it lives
  there because it runs before any scope exists.

Every statement here still carries an explicit ``org_id = :org_id`` predicate
even though row-level security would enforce it anyway. Two independent fences,
so a misconfigured database role cannot quietly become a cross-tenant read.

Both are run through ``core.scoped_sql.execute_scoped``, which refuses to execute
unless the session is already bound to the same scope. The ORM guard does not
inspect a ``text()`` clause, so without that check a scoped raw statement would
be trusted purely because its author remembered the predicate.
"""

from __future__ import annotations

from sqlalchemy import TextClause, text

#: docs/AGENT-PROTOCOL.md §3, verbatim in intent: select queued jobs for this org
#: only, skip rows another transaction already holds, and stamp the lease and the
#: attempt counter in the same statement that changes the status. A read followed
#: by a write would let two agents claim the same job.
CLAIM_JOBS: TextClause = text(
    """
    UPDATE scan_jobs
       SET status = 'claimed',
           agent_id = :agent_id,
           lease_expires_at = now() + make_interval(secs => :lease_seconds),
           attempts = attempts + 1,
           updated_at = now()
     WHERE id IN (
       SELECT id
         FROM scan_jobs
        WHERE org_id = :org_id
          AND status = 'queued'
          AND attempts < :max_attempts
        ORDER BY created_at
        LIMIT :capacity
        FOR UPDATE SKIP LOCKED
     )
    RETURNING id, target, profile, lease_expires_at
    """
)

#: Which of the submitted addresses fall inside a network this org has
#: registered. Returns the *accepted* set; the caller rejects the difference, so
#: a query returning nothing rejects everything rather than accepting everything.
#:
#: The candidates are unnested as ``text`` and cast to ``inet`` only inside the
#: predicate, so the rows come back as the exact strings the caller passed in.
#: Returning ``inet`` and casting it back would not round-trip: ``'10.0.4.12'::
#: inet::text`` is ``'10.0.4.12/32'``, which matches no submitted address and
#: would silently reject every host.
HOSTS_INSIDE_REGISTERED_NETWORKS: TextClause = text(
    """
    SELECT DISTINCT candidate.ip AS ip
      FROM unnest(CAST(:ips AS text[])) AS candidate(ip)
     WHERE EXISTS (
       SELECT 1
         FROM networks
        WHERE networks.org_id = :org_id
          AND networks.cidr >>= CAST(candidate.ip AS inet)
     )
    """
)
