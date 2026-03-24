import { useEffect, useState, useRef } from 'react';
import { Server, Database, User, Network, HardDrive, Image, Globe, Loader2, CheckCircle2, XCircle } from 'lucide-react';
import { ServiceType } from '@/lib/types';

const serviceIcons: Record<ServiceType, React.ReactNode> = {
  ec2: <Server size={16} />,
  s3: <Database size={16} />,
  iam: <User size={16} />,
  vpc: <Network size={16} />,
  rds: <Database size={16} />,
  ebs: <HardDrive size={16} />,
  ami: <Image size={16} />,
  elb: <Globe size={16} />,
};

const serviceLabels: Record<ServiceType, string> = {
  ec2: 'EC2', s3: 'S3', iam: 'IAM', vpc: 'VPC',
  rds: 'RDS', ebs: 'EBS', ami: 'AMI', elb: 'ELB',
};

export type ServiceStatus = 'pending' | 'scanning' | 'done' | 'error' | 'cancelled';

interface ProgressRow {
  service: ServiceType;
  status: ServiceStatus;
  message: string;
}

interface ScanProgressProps {
  rows: ProgressRow[];
  onBack: () => void;
  onStop: () => void;
  canStop: boolean;
  isStopping: boolean;
}

function ElapsedTimer({ running }: { running: boolean }) {
  const [seconds, setSeconds] = useState(0);
  const startRef = useRef(Date.now());

  useEffect(() => {
    if (!running) return;
    startRef.current = Date.now();
    setSeconds(0);
    const interval = setInterval(() => {
      setSeconds(Math.floor((Date.now() - startRef.current) / 1000));
    }, 1000);
    return () => clearInterval(interval);
  }, [running]);

  if (!running && seconds === 0) return null;

  return (
    <span className="text-[10px] text-muted-foreground/70 tabular-nums font-mono">
      {seconds}s
    </span>
  );
}

export default function ScanProgress({ rows, onBack, onStop, canStop, isStopping }: ScanProgressProps) {
  return (
    <div className="glass rounded-2xl p-6">
      <h2 className="mb-4 text-sm font-bold text-foreground uppercase tracking-wider">Scan Progress</h2>
      <div className="space-y-2">
        {rows.map(row => (
          <div
            key={row.service}
            className={`flex items-center gap-3 rounded-xl px-4 py-3 transition-all ${
              row.status === 'scanning'
                ? 'glass-subtle border-primary/20'
                : 'bg-muted/20'
            }`}
            style={{ borderWidth: row.status === 'scanning' ? 1 : 0 }}
          >
            <span className={`${row.status === 'scanning' ? 'text-primary' : 'text-muted-foreground'}`}>
              {serviceIcons[row.service]}
            </span>
            <span className="w-10 text-xs font-bold text-foreground">{serviceLabels[row.service]}</span>
            <div className="flex-1 truncate text-[11px] text-muted-foreground">
              {row.message || (row.status === 'pending' ? 'Waiting...' : '')}
            </div>
            <ElapsedTimer running={row.status === 'scanning'} />
            <div>
              {row.status === 'scanning' && <Loader2 size={16} className="animate-spin text-primary" />}
              {row.status === 'done' && <CheckCircle2 size={16} className="text-health-secure" />}
              {row.status === 'error' && <XCircle size={16} className="text-severity-critical" />}
              {row.status === 'cancelled' && <XCircle size={16} className="text-foreground/50" />}
              {row.status === 'pending' && <div className="h-1.5 w-1.5 rounded-full bg-muted-foreground/20" />}
            </div>
          </div>
        ))}
      </div>
      <div className="mt-4 flex items-center gap-4">
        <button
          onClick={onBack}
          className="text-[11px] text-foreground/60 hover:text-foreground transition-colors"
        >
          &larr; Back
        </button>
        {canStop && (
          <button
            onClick={onStop}
            disabled={isStopping}
            className="text-[11px] text-severity-critical/80 hover:text-severity-critical disabled:cursor-not-allowed disabled:opacity-50 transition-colors"
          >
            Stop Scan
          </button>
        )}
      </div>
    </div>
  );
}
