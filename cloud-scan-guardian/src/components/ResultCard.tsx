import { useState } from 'react';
import { ChevronDown, ChevronRight, ExternalLink, Link2 } from 'lucide-react';
import { ServiceAnalysis, Finding, AttackPath, Severity } from '@/lib/types';
import { SeverityBadge, HealthBadge } from './SeverityBadge';
import CopyButton from './CopyButton';
import ExportButton from './ExportButton';
import { format } from 'date-fns';

const severityOrder: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NEEDS_REVIEW'];

function Collapsible({ label, children, defaultOpen = false }: { label: string; children: React.ReactNode; defaultOpen?: boolean }) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div>
      <button onClick={() => setOpen(!open)} className="flex items-center gap-1.5 text-xs font-medium text-foreground/70 hover:text-foreground transition-colors">
        {open ? <ChevronDown size={13} /> : <ChevronRight size={13} />}
        {label}
      </button>
      {open && <div className="mt-2 pl-4">{children}</div>}
    </div>
  );
}

function FindingCard({ finding }: { finding: Finding }) {
  return (
    <div className="glass-subtle rounded-xl p-5 space-y-3">
      <div className="flex flex-wrap items-center gap-2.5">
        <SeverityBadge severity={finding.severity} />
        <code className="text-xs font-mono text-muted-foreground/80">{finding.id}</code>
        <span className="rounded-md bg-muted/50 px-2 py-0.5 text-xs text-muted-foreground">{finding.resource_type}</span>
        <span className="rounded-md bg-muted/50 px-2 py-0.5 text-xs text-muted-foreground">{finding.category}</span>
        {finding.attack_path_ids?.length > 0 && (
          <span className="rounded-md bg-primary/10 px-2 py-0.5 text-xs text-primary font-semibold flex items-center gap-1">
            <Link2 size={10} /> Chain
          </span>
        )}
      </div>
      <div>
        <p className="text-base font-semibold text-foreground">{finding.issue_title}</p>
        <p className="mt-1 text-sm text-muted-foreground leading-relaxed">{finding.issue_description}</p>
      </div>
      <div className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground/70 font-mono">
        <span>{finding.resource_name}</span>
        <span className="opacity-30">/</span>
        <span>{finding.resource_id}</span>
      </div>
      <div className="space-y-2">
        <Collapsible label="Impact">
          <p className="text-sm text-muted-foreground leading-relaxed">{finding.impact}</p>
        </Collapsible>
        <Collapsible label="Fix Command">
          <div className="relative rounded-xl bg-black p-4 font-mono text-sm text-white overflow-x-auto border border-[hsl(0_0%_100%/0.08)]">
            <div className="absolute right-2 top-2"><CopyButton text={finding.fix_command} /></div>
            <pre className="whitespace-pre-wrap pr-16">{finding.fix_command}</pre>
          </div>
        </Collapsible>
        <Collapsible label="Explanation">
          <p className="text-sm text-muted-foreground leading-relaxed">{finding.fix_explanation}</p>
        </Collapsible>
      </div>
      {finding.aws_doc_reference && (
        <a href={finding.aws_doc_reference} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 text-xs text-primary/80 hover:text-primary transition-colors">
          <ExternalLink size={11} /> AWS Docs
        </a>
      )}
    </div>
  );
}

function AttackPathCard({ path }: { path: AttackPath }) {
  return (
    <div className="glass-subtle rounded-xl p-5 space-y-4">
      <div className="flex flex-wrap items-center gap-2.5">
        <SeverityBadge severity={path.severity} />
        <code className="text-xs font-mono text-muted-foreground/80">{path.id}</code>
        <span className="text-base font-semibold text-foreground">{path.title}</span>
      </div>

      {/* Chain */}
      <div className="space-y-0 pl-1">
        {path.chain.map((step, i) => (
          <div key={i} className="flex items-start gap-3">
            <div className="flex flex-col items-center">
              <div className="flex h-7 w-7 items-center justify-center rounded-full border border-primary/30 bg-primary/10 text-[10px] font-bold text-primary">
                {step.step}
              </div>
              {i < path.chain.length - 1 && <div className="h-5 w-px bg-primary/15" />}
            </div>
            <div className="pb-2">
              <p className="text-base font-semibold text-foreground">{step.resource_name}</p>
              <p className="text-sm text-muted-foreground/80">{step.action}</p>
              <div className="mt-1 flex items-center gap-2">
                <span className={`rounded-md px-1.5 py-0.5 text-xs font-bold uppercase tracking-wider ${
                  step.evidence_status === 'CONFIRMED'
                    ? 'bg-health-secure/15 text-health-secure'
                    : 'bg-severity-medium/10 text-severity-medium'
                }`}>
                  {step.evidence_status}
                </span>
                <span className="text-xs text-muted-foreground/65">{step.evidence}</span>
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Path summary */}
      <div className="rounded-xl bg-black px-4 py-3 font-mono text-sm text-white border border-[hsl(0_0%_100%/0.08)]">
        {path.full_path_summary}
      </div>

      <Collapsible label="Impact" defaultOpen>
        <p className="text-sm text-muted-foreground leading-relaxed">{path.impact}</p>
      </Collapsible>

      {/* Remediation Priority — hidden until data is properly populated
      {path.remediation_priority?.length > 0 && (
        <Collapsible label="Remediation Priority" defaultOpen>
          <ol className="list-decimal pl-4 space-y-1 text-sm text-muted-foreground">
            {path.remediation_priority.map((r, i) => (
              <li key={i}>
                <code className="text-primary text-xs">{r.finding_id}</code> &mdash; {r.action}
              </li>
            ))}
          </ol>
        </Collapsible>
      )}
      */}
    </div>
  );
}

const tabs = ['Summary', 'Narrative', 'Quick Wins', 'Findings', 'Attack Paths'] as const;

export default function ResultCard({ analysis }: { analysis: ServiceAnalysis }) {
  const [activeTab, setActiveTab] = useState<typeof tabs[number]>('Summary');
  const summary = analysis.account_summary;
  const sortedFindings = [...analysis.findings].sort(
    (a, b) => severityOrder.indexOf(a.severity) - severityOrder.indexOf(b.severity)
  );

  return (
    <div className="glass rounded-2xl overflow-hidden">
      {/* Tab bar + export */}
      <div className="flex border-b border-[hsl(0_0%_100%/0.05)]">
        <div className="flex flex-1 overflow-x-auto">
          {tabs.map(tab => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              className={`whitespace-nowrap px-4 py-3.5 text-xs font-semibold uppercase tracking-wider transition-all ${
                activeTab === tab
                  ? 'border-b-2 border-primary text-primary'
                  : 'text-foreground/50 hover:text-foreground'
              }`}
            >
              {tab}
              {tab === 'Findings' && <span className="ml-1 opacity-50">({analysis.findings.length})</span>}
              {tab === 'Attack Paths' && <span className="ml-1 opacity-50">({analysis.attack_paths.length})</span>}
            </button>
          ))}
        </div>
        <div className="flex items-center pr-4">
          <ExportButton analysis={analysis} />
        </div>
      </div>

      <div className="p-6">
        {activeTab === 'Summary' && (
          <div className="space-y-5">
            <div className="flex flex-wrap items-center gap-3">
              <span className="text-xl font-extrabold text-gradient uppercase">{analysis.service}</span>
              <HealthBadge health={summary.overall_health} />
              <span className="text-xs text-muted-foreground/70">
                {format(new Date(analysis.scan_timestamp), 'PPpp')}
              </span>
            </div>
            <div className="flex flex-wrap gap-2">
              {severityOrder.map(sev => (
                <SeverityBadge key={sev} severity={sev} count={summary.severity_breakdown[sev] || 0} />
              ))}
            </div>
            <div className="grid grid-cols-3 gap-3 text-center">
              {[
                { value: summary.total_resources_scanned, label: 'Resources' },
                { value: summary.total_findings, label: 'Findings' },
                { value: summary.total_attack_paths, label: 'Attack Paths' },
              ].map(stat => (
                <div key={stat.label} className="glass-subtle rounded-xl p-4">
                  <p className="text-2xl font-extrabold text-foreground">{stat.value}</p>
                  <p className="text-xs text-muted-foreground/70 uppercase tracking-wider font-semibold mt-1">{stat.label}</p>
                </div>
              ))}
            </div>
          </div>
        )}

        {activeTab === 'Narrative' && (
          <div className="text-sm text-foreground/85 leading-relaxed whitespace-pre-wrap">
            {analysis.narrative || 'No narrative available.'}
          </div>
        )}

        {activeTab === 'Quick Wins' && (
          <div className="space-y-2.5">
            {analysis.quick_wins?.length ? analysis.quick_wins.map((qw, i) => (
              <div key={i} className="glass-subtle rounded-xl p-4 space-y-1.5 border-l-2 border-health-secure/40">
                <div className="flex items-center gap-2">
                  <code className="rounded-md bg-primary/10 px-2 py-0.5 text-xs font-mono text-primary font-bold">{qw.finding_id}</code>
                  <span className="rounded-md bg-muted/50 px-2 py-0.5 text-xs text-muted-foreground">{qw.effort}</span>
                </div>
                <p className="text-base font-medium text-foreground">{qw.action}</p>
                <p className="text-sm text-muted-foreground/80">{qw.impact}</p>
              </div>
            )) : (
              <p className="text-sm text-muted-foreground/70">No quick wins identified.</p>
            )}
          </div>
        )}

        {activeTab === 'Findings' && (
          <div className="space-y-3">
            {sortedFindings.length ? sortedFindings.map(f => (
              <FindingCard key={f.id} finding={f} />
            )) : (
              <p className="text-sm text-muted-foreground/70">No findings.</p>
            )}
          </div>
        )}

        {activeTab === 'Attack Paths' && (
          <div className="space-y-3">
            {analysis.attack_paths?.length ? analysis.attack_paths.map(ap => (
              <AttackPathCard key={ap.id} path={ap} />
            )) : (
              <p className="text-sm text-muted-foreground/70">No attack paths identified.</p>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
