-- Create the application role. Run once per database, as a superuser, BEFORE
-- `alembic upgrade head` (migration 0003 grants privileges to this role and
-- now fails with an explanatory error if it does not exist, rather than skipping).
--
-- The role is deliberately NOSUPERUSER and NOBYPASSRLS: both attributes make
-- PostgreSQL skip Row-Level Security entirely, which would remove the backstop
-- that catches a bug in the query layer.
--
--   psql -v role_password="'<generated>'" -f scripts/bootstrap_db.sql -d threatsculpt_dev
--
-- Generate the password out of band and put it in TS_DATABASE_URL. Do not
-- commit it; do not hardcode it here.

\set role_name threatsculpt_app

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'threatsculpt_app') THEN
        EXECUTE format('CREATE ROLE threatsculpt_app LOGIN PASSWORD %L', :role_password);
    ELSE
        EXECUTE format('ALTER ROLE threatsculpt_app LOGIN PASSWORD %L', :role_password);
    END IF;
END
$$;

ALTER ROLE threatsculpt_app NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;

GRANT CONNECT ON DATABASE :"DBNAME" TO threatsculpt_app;
