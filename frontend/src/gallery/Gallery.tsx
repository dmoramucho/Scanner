import {
  AiPanel,
  ConfidenceBadge,
  FactPanel,
  InferredValue,
  KevBadge,
  ManagementBadge,
  PriorityBadge,
  ReviewStateBadge,
  VersionSourceBadge,
} from '../components';
import {
  CONFIDENCE_STATES,
  INSIGHT_STATES,
  MANAGEMENT_STATES,
  PRIORITIES,
  VERSION_SOURCES,
} from '../types/api';
import { CITATIONS, INFERRED_VLAN, PROPOSED_INSIGHT, RATIONALE, WORKLIST } from '../mock/fixtures';
import './Gallery.css';

/**
 * Every component, in every state, on one page.
 *
 * Not documentation — a working surface. The three distinctions only earn their keep if they
 * stay consistent across screens nobody has written yet, and the way to notice drift is to be
 * able to see the whole language at once (m4-design §3).
 *
 * Each section is driven by the union's own tuple (`CONFIDENCE_STATES`, …), so a state added
 * to the API contract appears here automatically rather than being forgotten in a
 * hand-maintained list.
 */
export function Gallery() {
  return (
    <main className="gallery">
      <h1 className="gallery__title">The visual language</h1>
      <p className="gallery__lede">
        Three distinctions and five recurring signals, defined once and reused everywhere. An
        analyst learns these here and reads every screen with them. Colour carries meaning: the
        palette is deliberately quiet so that the one signal allowed to shout — KEV — actually does.
      </p>

      <section className="gallery__section">
        <h2 className="gallery__section-title">1 · Confidence — how well we know the version</h2>
        <p className="gallery__note">
          <strong>Confirmed</strong> came from the device&rsquo;s own package database.{' '}
          <strong>Probable</strong> came from a banner, and a backported fix leaves the old version
          string in place — so it is a work queue (&ldquo;verify by logging in&rdquo;), not an
          alarm. That is why it is amber and not red.
        </p>
        <div className="gallery__row">
          {CONFIDENCE_STATES.map((state) => (
            <ConfidenceBadge key={state} state={state} />
          ))}
        </div>
      </section>

      <section className="gallery__section">
        <h2 className="gallery__section-title">2 · Management state — does anyone own it</h2>
        <p className="gallery__note">
          <strong>Shadow IT</strong> is the headline. <strong>Unknown</strong> means the
          managed-record match was ambiguous, and it is grey on purpose: the backend refuses to
          count it as shadow IT, and the interface must refuse just as hard.
        </p>
        <div className="gallery__row">
          {MANAGEMENT_STATES.map((state) => (
            <ManagementBadge key={state} state={state} />
          ))}
        </div>
      </section>

      <section className="gallery__section">
        <h2 className="gallery__section-title">3 · Fact vs AI — who said this</h2>
        <p className="gallery__note">
          Deterministic facts and model output never share a surface. AI content carries a tinted
          panel, a coloured rule, the word AI-GENERATED, its citations, its own confidence, and
          where it sits in human review — every time, because they are the things that let an
          analyst check its work.
        </p>
        <div className="gallery__pair">
          <FactPanel label="Deterministic match">
            <div className="gallery__row" style={{ border: 'none', padding: 0 }}>
              <KevBadge />
              <ConfidenceBadge state="confirmed" />
              <VersionSourceBadge source="package_manager" />
            </div>
            <p className="gallery__mono" style={{ marginBottom: 0 }}>
              {WORKLIST.findings[0]?.matched_cpe}
            </p>
          </FactPanel>

          <AiPanel
            recommendation={PROPOSED_INSIGHT.recommendation}
            confidence={PROPOSED_INSIGHT.confidence}
            state={PROPOSED_INSIGHT.state}
            citations={CITATIONS}
            kevLocked={PROPOSED_INSIGHT.kev_locked_visible}
            modelVersion={PROPOSED_INSIGHT.model_version}
          >
            {RATIONALE}
          </AiPanel>
        </div>
      </section>

      <section className="gallery__section">
        <h2 className="gallery__section-title">Review state</h2>
        <p className="gallery__note">
          Part of the AI distinction rather than a signal of its own: &ldquo;a model suggested
          this&rdquo; and &ldquo;a person agreed&rdquo; are different claims.
        </p>
        <div className="gallery__row">
          {INSIGHT_STATES.map((state) => (
            <ReviewStateBadge key={state} state={state} />
          ))}
        </div>
      </section>

      <section className="gallery__section">
        <h2 className="gallery__section-title">KEV — the one signal allowed to shout</h2>
        <div className="gallery__row">
          <KevBadge />
          <KevBadge locked={false} />
        </div>
      </section>

      <section className="gallery__section">
        <h2 className="gallery__section-title">Priority — the band, and why</h2>
        <p className="gallery__note">
          Every band travels with the sentence that produced it. The client never recomputes one: a
          second implementation of the policy would drift, and the interface&rsquo;s version would
          win because it is the one people see.
        </p>
        <div className="gallery__stack">
          <div className="gallery__row">
            {PRIORITIES.map((priority) => (
              <PriorityBadge
                key={priority}
                priority={priority}
                reason={`Example reason for ${priority.toUpperCase()}.`}
              />
            ))}
          </div>
          <div className="gallery__row">
            <PriorityBadge
              priority={WORKLIST.findings[0]?.priority ?? 'p1'}
              reason={WORKLIST.findings[0]?.priority_reason ?? ''}
              rule={WORKLIST.findings[0]?.priority_rule ?? ''}
              showReason
            />
          </div>
        </div>
      </section>

      <section className="gallery__section">
        <h2 className="gallery__section-title">Version source, and inferred values</h2>
        <p className="gallery__note">
          A credentialed read is ground truth; a banner is a claim. And a VLAN label is derived from
          the operator&rsquo;s subnet map rather than measured — so it is marked <em>inferred</em>,
          and an address outside every mapped range reads as <em>unknown</em>, never as a plausible
          VLAN.
        </p>
        <div className="gallery__row">
          {VERSION_SOURCES.map((source) => (
            <VersionSourceBadge key={source} source={source} />
          ))}
          <InferredValue value={INFERRED_VLAN} label="VLAN" />
          <InferredValue value={null} label="VLAN" />
        </div>
      </section>

      <section className="gallery__section">
        <h2 className="gallery__section-title">At density — the language on a worklist</h2>
        <p className="gallery__note">
          The test that matters: hundreds of rows, and the urgent one still finds you. This is the
          shape Triage Home takes in P21.
        </p>
        <table className="gallery__table">
          <thead>
            <tr>
              <th>Asset</th>
              <th>CVE</th>
              <th>Priority</th>
              <th>Confidence</th>
              <th>Source</th>
              <th>Management</th>
            </tr>
          </thead>
          <tbody>
            {WORKLIST.findings.map((finding) => (
              <tr key={finding.match_id}>
                <td>{finding.asset_label}</td>
                <td className="gallery__mono">
                  {finding.cve_id} {finding.kev ? <KevBadge /> : null}
                </td>
                <td>
                  <PriorityBadge
                    priority={finding.priority}
                    reason={finding.priority_reason}
                    rule={finding.priority_rule}
                  />
                </td>
                <td>
                  <ConfidenceBadge state={finding.confidence_state} />
                </td>
                <td>
                  <VersionSourceBadge source={finding.version_source} />
                </td>
                <td>
                  <ManagementBadge state={finding.management_state} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
    </main>
  );
}
