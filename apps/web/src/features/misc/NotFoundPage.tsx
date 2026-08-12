import { EmptyState } from '@/components/ui/States';
import { ButtonLink } from '@/components/ui/Button';

export function NotFoundPage() {
  return (
    <main className="main" id="main">
      <EmptyState
        icon="search"
        title="That page does not exist"
        body="The link may be out of date, or the resource may belong to a different organisation — ThreatSculpt reports both the same way, deliberately, so a wrong guess reveals nothing."
        action={
          <ButtonLink to="/" variant="primary">
            Back to your risk posture
          </ButtonLink>
        }
      />
    </main>
  );
}
