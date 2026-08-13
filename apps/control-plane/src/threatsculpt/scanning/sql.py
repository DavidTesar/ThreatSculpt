"""The statements that have to be raw SQL, kept together and explained.

Everything else in this package goes through ``ScopedRepository``. These do not,
because each needs something the ORM cannot express:

* ``CLAIM_JOBS`` needs ``FOR UPDATE SKIP LOCKED`` inside a subquery of an UPDATE,
  which is the exact shape docs/AGENT-PROTOCOL.md §3 mandates. Without SKIP
  LOCKED two agents polling at once serialise on the same row and one of them
  gets a job the other already took.
* ``CANCEL_JOBS_LOSING_AUTHORIZATION`` needs ``UPDATE ... FROM`` a CTE so the
  status a job held *before* it was cancelled comes back in the same round trip
  that cancels it; ``RETURNING`` alone yields only the new row.
* ``HOSTS_INSIDE_REGISTERED_NETWORKS`` checks a whole batch of submitted
  addresses against the org's networks in one round trip using the native
  ``cidr >>= inet`` operator. The alternative — fetching every network and
  looping in Python — is either unbounded or silently truncated.
* ``CONSUME_ENROLLMENT_TOKEN`` (in ``agents.enrollment``) is the third; it lives
  there because it runs before any scope exists.

Every statement here still carries an explicit ``org_id = :org_id`` predicate
even though row-level security would enforce it anyway. Two independent fences,
so a misconfigured database role cannot quietly become a cross-tenant read.

All of them are run through ``core.scoped_sql.execute_scoped``, which refuses to execute
unless the session is already bound to the same scope. The ORM guard does not
inspect a ``text()`` clause, so without that check a scoped raw statement would
be trusted purely because its author remembered the predicate.
"""

from __future__ import annotations

from sqlalchemy import TextClause, text

#: The containment predicate, shared by the claim query and by the re-validation
#: pass in ``scanning.containment`` so the two can never disagree about what
#: "still authorised" means. ``>>=`` is *contains or equals*, and the row it is
#: applied to supplies both ``org_id`` and ``target``.
STILL_AUTHORIZED_SQL = """
       EXISTS (
         SELECT 1
           FROM networks
          WHERE networks.org_id = scan_jobs.org_id
            AND networks.authorized
            AND networks.cidr >>= scan_jobs.target
       )
"""

#: Marker the two statements below carry where the predicate belongs.
#:
#: Substituted rather than f-string-interpolated for a reason worth stating: an
#: f-string here is indistinguishable, to a reader and to a linter, from the
#: shape that builds SQL out of a request value. Nothing in this module ever
#: does that — every value is a bind parameter — and keeping the statements
#: plain string literals is how that stays obvious.
_AUTHORIZED_MARKER = "-- {still_authorized}"


def _compose(template: str) -> TextClause:
    """The template with its containment predicate substituted in.

    ``template`` is a module-level literal and the substituted text is the
    module-level constant above. No caller input reaches either.
    """
    return text(template.replace(_AUTHORIZED_MARKER, STILL_AUTHORIZED_SQL))


#: docs/AGENT-PROTOCOL.md §3, verbatim in intent: select queued jobs for this org
#: only, skip rows another transaction already holds, and stamp the lease and the
#: attempt counter in the same statement that changes the status. A read followed
#: by a write would let two agents claim the same job.
#:
#: The containment predicate is *not* an optimisation. Authorisation was checked
#: once, when the job was created, and a job can sit queued for as long as the
#: fleet is busy. Without re-checking here, revoking permission — the one action
#: an operator takes when they want the packets to stop — did not stop anything:
#: the next poll still handed the agent the target. Authorisation that can be
#: granted but not withdrawn is not authorisation, so the claim itself asks the
#: question again, against the state of ``networks`` at the moment of the claim.
#: ``containment.revalidate_open_jobs`` closes the same hole for jobs that are
#: already leased; this predicate is what makes the queued case impossible
#: regardless of whether that pass ran.
CLAIM_JOBS: TextClause = _compose(
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
          AND -- {still_authorized}
        ORDER BY created_at
        LIMIT :capacity
        FOR UPDATE SKIP LOCKED
     )
    RETURNING id, target, profile, lease_expires_at
    """
)

#: The other half of withdrawal: jobs that are already leased.
#:
#: ``CLAIM_JOBS`` stops a queued job from ever being handed out again, but a job
#: that an agent claimed thirty seconds before the operator revoked permission is
#: already in that agent's hands. Cancelling is the only lever the control plane
#: has over it — it releases the lease, so the agent's next ``/status`` or
#: ``/results`` call is refused with 409 and docs/AGENT-PROTOCOL.md §6 tells it to
#: drop the work. Deleting the row instead would destroy the record of a scan
#: that may already have sent packets, which is the opposite of what an operator
#: withdrawing authorisation needs to be able to prove afterwards.
#:
#: The CTE captures the prior status so the audit row can say what was actually
#: interrupted; the outer statement repeats the status predicate so two
#: concurrent withdrawals cancel the same job once rather than twice.
CANCEL_JOBS_LOSING_AUTHORIZATION: TextClause = _compose(
    """
    WITH withdrawn AS (
      SELECT id, status
        FROM scan_jobs
       WHERE org_id = :org_id
         AND status IN ('queued', 'claimed', 'running')
         AND NOT -- {still_authorized}
    )
    UPDATE scan_jobs
       SET status = 'cancelled',
           agent_id = NULL,
           lease_expires_at = NULL,
           finished_at = now(),
           error = :reason,
           updated_at = now()
      FROM withdrawn
     WHERE scan_jobs.id = withdrawn.id
       AND scan_jobs.org_id = :org_id
       AND scan_jobs.status IN ('queued', 'claimed', 'running')
    RETURNING scan_jobs.id AS id,
              CAST(scan_jobs.target AS text) AS target,
              withdrawn.status AS previous_status
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
