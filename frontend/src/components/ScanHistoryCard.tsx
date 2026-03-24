import { Trash2, CheckCircle2, XCircle, Loader2 } from 'lucide-react';
import { ScanSummary, ServiceType } from '@/lib/types';
import { formatDistanceToNow } from 'date-fns';

const serviceLabels: Record<ServiceType, string> = {
  ec2: 'EC2', s3: 'S3', iam: 'IAM', vpc: 'VPC',
  rds: 'RDS', ebs: 'EBS', ami: 'AMI', elb: 'ELB',
};

const healthColors: Record<string, string> = {
  SECURE: 'text-health-secure',
  MOSTLY_SECURE: 'text-[hsl(199_89%_48%)]',
  AT_RISK: 'text-severity-high',
  CRITICAL_RISK: 'text-severity-critical',
  SCAN_INCOMPLETE: 'text-muted-foreground',
};

interface Props {
  sessionId: string;
  scans: ScanSummary[];
  onSelect: (scanId: string) => void;
  onDelete: (sessionId: string) => void;
}

export default function ScanHistoryCard({ sessionId, scans, onSelect, onDelete }: Props) {
  if (scans.length === 0) return null;

  const first = scans[0];
  const timeAgo = formatDistanceToNow(new Date(first.started_at), { addSuffix: true });

  const totals = scans.reduce(
    (acc, s) => ({
      critical: acc.critical + s.severity_critical,
      high: acc.high + s.severity_high,
      medium: acc.medium + s.severity_medium,
    }),
    { critical: 0, high: 0, medium: 0 }
  );

  const healthRank = ['CRITICAL_RISK', 'AT_RISK', 'MOSTLY_SECURE', 'SECURE', 'SCAN_INCOMPLETE'];
  const worstHealth = scans.reduce<string | null>((worst, s) => {
    if (!s.overall_health) return worst;
    if (!worst) return s.overall_health;
    return healthRank.indexOf(s.overall_health) < healthRank.indexOf(worst) ? s.overall_health : worst;
  }, null);

  return (
    <div
      className="group relative glass-subtle rounded-xl p-3 cursor-pointer card-hover transition-all"
      onClick={() => onSelect(sessionId)}
    >
      {/* Delete */}
      <button
        onClick={(e) => { e.stopPropagation(); onDelete(sessionId); }}
        className="absolute right-2 top-2 hidden group-hover:block text-foreground/40 hover:text-severity-critical transition-colors"
        title="Delete"
      >
        <Trash2 size={12} />
      </button>

      {/* Time + region */}
      <div className="flex items-center gap-1.5 text-[10px] text-foreground/60 mb-2">
        <span>{timeAgo}</span>
        <span className="opacity-30">/</span>
        <span className="font-mono">{first.region}</span>
      </div>

      {/* Service badges */}
      <div className="flex flex-wrap gap-1 mb-2">
        {scans.map(s => (
          <span
            key={s.id}
            className="inline-flex items-center gap-1 rounded-md bg-muted/50 px-1.5 py-0.5 text-[10px] font-medium text-foreground/80"
            onClick={(e) => { e.stopPropagation(); onSelect(s.id); }}
          >
            {s.status === 'completed' && <CheckCircle2 size={9} className="text-health-secure" />}
            {s.status === 'failed' && <XCircle size={9} className="text-severity-critical" />}
            {s.status === 'cancelled' && <XCircle size={9} className="text-foreground/50" />}
            {s.status === 'running' && <Loader2 size={9} className="animate-spin text-primary" />}
            {serviceLabels[s.service] || s.service.toUpperCase()}
          </span>
        ))}
      </div>

      {/* Severity + health */}
      <div className="flex items-center gap-1.5 text-[10px] font-bold">
        {totals.critical > 0 && <span className="text-severity-critical">{totals.critical}C</span>}
        {totals.high > 0 && <span className="text-severity-high">{totals.high}H</span>}
        {totals.medium > 0 && <span className="text-severity-medium">{totals.medium}M</span>}
        {totals.critical === 0 && totals.high === 0 && totals.medium === 0 && (
          <span className="text-foreground/50 font-normal">
            {scans.some(s => s.status === 'cancelled') ? 'Cancelled' : 'No findings'}
          </span>
        )}
        {worstHealth && (
          <>
            <span className="text-muted-foreground/20 font-normal mx-0.5">|</span>
            <span className={`font-semibold ${healthColors[worstHealth] || 'text-muted-foreground'}`}>
              {worstHealth.replace(/_/g, ' ')}
            </span>
          </>
        )}
      </div>
    </div>
  );
}
