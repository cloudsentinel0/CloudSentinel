import { useState, useEffect, useCallback, useRef } from 'react';
import { AnimatePresence, motion } from 'framer-motion';
import { Shield, RotateCcw } from 'lucide-react';
import { LLMProvider, ServiceType, ServiceAnalysis, SSEEvent, ErrorCategory } from '@/lib/types';
import { cancelScan, checkHealth, startScan, getScan } from '@/lib/api';
import ScanConfiguration from '@/components/ScanConfiguration';
import ScanProgress, { ServiceStatus } from '@/components/ScanProgress';
import ResultCard from '@/components/ResultCard';
import ScanHistoryPanel from '@/components/ScanHistorySidebar';
import { useScanHistory } from '@/hooks/use-scan-history';
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog';

type View = 'config' | 'scanning' | 'history-detail';

interface ServiceProgress {
  service: ServiceType;
  status: ServiceStatus;
  message: string;
}

const ERROR_HELP: Record<ErrorCategory, string> = {
  auth: 'Check that your AWS credentials are correct and have the required IAM permissions.',
  timeout: 'The scan took too long. Try selecting fewer services or check your network.',
  unknown: '',
};

export default function Index() {
  const [view, setView] = useState<View>('config');
  const [backendOnline, setBackendOnline] = useState<boolean | null>(null);
  const [serviceProgress, setServiceProgress] = useState<ServiceProgress[]>([]);
  const [results, setResults] = useState<Map<ServiceType, ServiceAnalysis>>(new Map());
  const [errors, setErrors] = useState<Map<ServiceType, { message: string; category?: ErrorCategory }>>(new Map());
  const [scanDone, setScanDone] = useState(false);
  const [historyDetails, setHistoryDetails] = useState<ServiceAnalysis[]>([]);
  const [activeSessionId, setActiveSessionId] = useState<string | null>(null);
  const [showStopConfirm, setShowStopConfirm] = useState(false);
  const [isStopping, setIsStopping] = useState(false);
  const abortRef = useRef<AbortController | null>(null);

  const { sessions, refresh: refreshHistory, remove: removeSession } = useScanHistory();

  useEffect(() => {
    checkHealth()
      .then(() => setBackendOnline(true))
      .catch(() => setBackendOnline(false));
  }, []);

  const resetToConfig = useCallback(() => {
    abortRef.current = null;
    setActiveSessionId(null);
    setScanDone(false);
    setShowStopConfirm(false);
    setIsStopping(false);
    setServiceProgress([]);
    setResults(new Map());
    setErrors(new Map());
    setHistoryDetails([]);
    setView('config');
  }, []);

  const stopActiveScan = useCallback(async () => {
    const sessionId = activeSessionId;
    setIsStopping(true);
    try {
      if (sessionId) {
        await cancelScan(sessionId).catch((err) => {
          console.error('Failed to request scan cancellation:', err);
        });
      }
    } finally {
      abortRef.current?.abort();
      refreshHistory();
      resetToConfig();
    }
  }, [activeSessionId, refreshHistory, resetToConfig]);

  const handleStartScan = useCallback((config: {
    accessKey: string;
    secretKey: string;
    region: string;
    sessionToken: string | null;
    services: ServiceType[];
    llmProvider: LLMProvider;
    profile: string | null;
    credentialMode: 'keys' | 'profile';
  }) => {
    setView('scanning');
    setScanDone(false);
    setResults(new Map());
    setErrors(new Map());
    setHistoryDetails([]);
    setShowStopConfirm(false);
    setIsStopping(false);

    const progress: ServiceProgress[] = config.services.map(s => ({
      service: s, status: 'pending' as ServiceStatus, message: '',
    }));
    setServiceProgress(progress);

    const sessionId = crypto.randomUUID();
    setActiveSessionId(sessionId);

    const controller = new AbortController();
    abortRef.current = controller;

    const handleEvent = (event: SSEEvent) => {
      if (event.type === 'progress') {
        setServiceProgress(prev =>
          prev.map(p =>
            p.service === event.service
              ? { ...p, status: 'scanning', message: event.message }
              : p
          )
        );
      } else if (event.type === 'result') {
        setResults(prev => new Map(prev).set(event.service, event.analysis));
        setServiceProgress(prev =>
          prev.map(p =>
            p.service === event.service
              ? { ...p, status: 'done', message: 'Complete' }
              : p
          )
        );
      } else if (event.type === 'error') {
        setErrors(prev => new Map(prev).set(event.service, {
          message: event.message,
          category: event.category,
        }));
        setServiceProgress(prev =>
          prev.map(p =>
            p.service === event.service
              ? { ...p, status: 'error', message: event.message }
              : p
          )
        );
      } else if (event.type === 'cancelled') {
        setServiceProgress(prev =>
          prev.map(p =>
            p.service === event.service
              ? { ...p, status: 'cancelled', message: event.message }
              : p
          )
        );
        setScanDone(true);
        refreshHistory();
      } else if (event.type === 'done') {
        setScanDone(true);
        refreshHistory();
      }
    };

    const credentials = config.credentialMode === 'keys'
      ? { accessKey: config.accessKey, secretKey: config.secretKey, sessionToken: config.sessionToken }
      : null;

    const request = {
      services: config.services,
      region: config.region,
      llm_provider: config.llmProvider,
      profile: config.profile,
      session_id: sessionId,
    };

    startScan(request, credentials, handleEvent, controller.signal).catch(err => {
      if (err.name !== 'AbortError') {
        console.error('Scan error:', err);
        setScanDone(true);
      }
    });
  }, [refreshHistory]);

  const handleBack = useCallback(() => {
    if (scanDone) {
      resetToConfig();
      refreshHistory();
      return;
    }
    void stopActiveScan();
  }, [refreshHistory, resetToConfig, scanDone, stopActiveScan]);

  const handleStopConfirm = useCallback(() => {
    void stopActiveScan();
  }, [stopActiveScan]);

  const handleReset = () => {
    resetToConfig();
    refreshHistory();
  };

  const handleSelectHistorySession = useCallback(async (sessionId: string) => {
    try {
      const scans = sessions.get(sessionId);
      if (!scans || scans.length === 0) return;

      // Load all completed scans in this session
      const details = await Promise.all(
        scans
          .filter(s => s.status === 'completed')
          .map(s => getScan(s.id))
      );

      const analyses = details
        .map(d => d.analysis_json)
        .filter((a): a is ServiceAnalysis => a !== null);

      if (analyses.length > 0) {
        setHistoryDetails(analyses);
        setView('history-detail');
      }
    } catch (err) {
      console.error('Failed to load session scans:', err);
    }
  }, [sessions]);

  const handleDeleteSession = useCallback(async (sessionId: string) => {
    await removeSession(sessionId);
  }, [removeSession]);

  const hasHistory = sessions.size > 0;

  const historyPanel = hasHistory ? (
    <motion.div
      initial={{ opacity: 0, x: 20 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ delay: 0.2 }}
      className="hidden lg:block w-72 flex-shrink-0"
    >
      <ScanHistoryPanel
        sessions={sessions}
        onSelectScan={handleSelectHistorySession}
        onDeleteSession={handleDeleteSession}
      />
    </motion.div>
  ) : null;

  // ── Config view ────────────────────────────────────────────────────────────
  if (view === 'config') {
    return (
      <div className="min-h-screen flex items-center justify-center p-4">
        <div className="w-full max-w-xl">
          {/* Header part of ScanConfiguration sits above */}
          <ScanConfiguration
            onStartScan={handleStartScan}
            isScanning={false}
            backendOnline={backendOnline}
            historySlot={hasHistory ? (
              <motion.div
                initial={{ opacity: 0, x: 20 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: 0.2 }}
              >
                <ScanHistoryPanel
                  sessions={sessions}
                  onSelectScan={handleSelectHistorySession}
                  onDeleteSession={handleDeleteSession}
                />
              </motion.div>
            ) : undefined}
          />
        </div>
      </div>
    );
  }

  // ── Scanning / history-detail views ────────────────────────────────────────
  return (
    <div className="min-h-screen">
      <div className="mx-auto max-w-4xl p-4 pt-8">
        {/* Main content — centered max-w-4xl column */}
        <div className="space-y-6">
            <AnimatePresence mode="wait">
              {view === 'history-detail' ? (
                <motion.div
                  key="history-detail"
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  exit={{ opacity: 0 }}
                  className="space-y-6"
                >
                  <div className="flex items-center gap-3">
                    <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-primary/12">
                      <Shield className="text-primary" size={18} />
                    </div>
                    <h1 className="text-lg font-extrabold text-gradient">CloudSentinel</h1>
                    <span className="text-[10px] text-foreground/40 uppercase tracking-widest font-semibold ml-1">History</span>
                  </div>

                  {/* Cards area — history panel floats level with result cards */}
                  <div className="relative space-y-6">
                    {hasHistory && (
                      <div className="hidden lg:block absolute left-[calc(100%+1.5rem)] top-0 w-72">
                        {historyPanel}
                      </div>
                    )}
                    {historyDetails.map((analysis) => (
                      <ResultCard key={analysis.service} analysis={analysis} />
                    ))}
                  </div>

                  <div className="text-center pt-2">
                    <button
                      onClick={handleReset}
                      className="inline-flex items-center gap-2 rounded-xl bg-gradient-to-r from-primary to-[hsl(230_80%_60%)] px-6 py-3 text-sm font-bold text-white hover:brightness-110 transition-all glow-primary"
                    >
                      <RotateCcw size={15} />
                      New Scan
                    </button>
                  </div>
                </motion.div>
              ) : (
                <motion.div
                  key="scanning"
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  exit={{ opacity: 0 }}
                  className="space-y-6"
                >
                  <div className="flex items-center gap-3">
                    <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-primary/12">
                      <Shield className="text-primary" size={18} />
                    </div>
                    <h1 className="text-lg font-extrabold text-gradient">CloudSentinel</h1>
                  </div>

                  {/* Cards area — history panel floats level with scan progress */}
                  <div className="relative space-y-6">
                    {hasHistory && (
                      <div className="hidden lg:block absolute left-[calc(100%+1.5rem)] top-0 w-72">
                        {historyPanel}
                      </div>
                    )}

                  <ScanProgress
                    rows={serviceProgress}
                    onBack={handleBack}
                    onStop={() => setShowStopConfirm(true)}
                    canStop={!scanDone}
                    isStopping={isStopping}
                  />

                  <AlertDialog open={showStopConfirm} onOpenChange={setShowStopConfirm}>
                    <AlertDialogContent className="border-primary/10 bg-background/95">
                      <AlertDialogHeader>
                        <AlertDialogTitle>Stop this scan?</AlertDialogTitle>
                        <AlertDialogDescription>
                          Are you sure you want to stop the current scan? The in-progress scan will be cancelled and you
                          will be returned to the home page.
                        </AlertDialogDescription>
                      </AlertDialogHeader>
                      <AlertDialogFooter>
                        <AlertDialogCancel disabled={isStopping}>Cancel</AlertDialogCancel>
                        <AlertDialogAction
                          onClick={(event) => {
                            event.preventDefault();
                            handleStopConfirm();
                          }}
                          className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
                        >
                          {isStopping ? 'Stopping...' : 'OK'}
                        </AlertDialogAction>
                      </AlertDialogFooter>
                    </AlertDialogContent>
                  </AlertDialog>

                  {/* Errors */}
                  {Array.from(errors.entries()).map(([service, err]) => (
                    <div key={service} className="glass rounded-2xl p-5 border-l-2 border-[hsl(var(--severity-critical)/0.5)]">
                      <p className="text-xs font-bold text-severity-critical uppercase tracking-wider">{service} &mdash; Error</p>
                      <p className="mt-1.5 text-xs text-foreground/75">{err.message}</p>
                      {err.category && ERROR_HELP[err.category] && (
                        <p className="mt-2 text-[11px] text-foreground/50 italic">{ERROR_HELP[err.category]}</p>
                      )}
                    </div>
                  ))}

                  {/* Results */}
                  {Array.from(results.entries()).map(([service, analysis]) => (
                    <motion.div key={service} initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}>
                      <ResultCard analysis={analysis} />
                    </motion.div>
                  ))}

                  {/* Skeleton */}
                  {!scanDone && results.size === 0 && errors.size === 0 && (
                    <div className="space-y-4">
                      {[1, 2].map(i => (
                        <div key={i} className="glass rounded-2xl p-6 scan-pulse">
                          <div className="h-4 w-32 rounded-lg bg-muted/30 mb-4" />
                          <div className="space-y-2.5">
                            <div className="h-3 w-full rounded-lg bg-muted/20" />
                            <div className="h-3 w-2/3 rounded-lg bg-muted/20" />
                          </div>
                        </div>
                      ))}
                    </div>
                  )}

                  </div>{/* end relative wrapper */}

                  {/* Done */}
                  {scanDone && (
                    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="text-center pt-2">
                      <button
                        onClick={handleReset}
                        className="inline-flex items-center gap-2 rounded-xl bg-gradient-to-r from-primary to-[hsl(230_80%_60%)] px-6 py-3 text-sm font-bold text-white hover:brightness-110 transition-all glow-primary"
                      >
                        <RotateCcw size={15} />
                        Scan Another
                      </button>
                    </motion.div>
                  )}
                </motion.div>
              )}
            </AnimatePresence>
          </div>
      </div>
    </div>
  );
}
