import { useState } from 'react'
import StatusBadge from '@/components/shared/StatusBadge'
import MetricCard from '@/components/shared/MetricCard'
import { useApi } from '@/hooks/useApi'
import type { Artifact } from '@/types/artifact'

interface BuildResponse { artifacts: Artifact[]; chain_id: string }
interface VerifyError { code: string; message: string; index: number | null }
interface VerifyResponse {
  valid: boolean
  content_integrity: string
  chain_continuity: string
  signature_status: string
  anchor_status: string
  completeness: string
  errors: VerifyError[]
}
interface TamperResponse { artifacts: Artifact[] }

export default function Lab3AuditChain() {
  const [entries, setEntries]     = useState<Artifact[]>([])
  const [chainId, setChainId]     = useState<string | null>(null)
  const [tampered, setTampered]   = useState(false)
  const [verified, setVerified]   = useState<VerifyResponse | null>(null)

  const { call: callBuild, loading: loadingBuild, error: buildError } = useApi<BuildResponse>()
  const { call: callVerify, loading: loadingVerify, error: verifyError } = useApi<VerifyResponse>()
  const { call: callTamper, loading: loadingTamper, error: tamperError } = useApi<TamperResponse>()

  const buildChain = async () => {
    const res = await callBuild('/api/chain/build', {})
    if (res) {
      setChainId(res.chain_id)
      setEntries(res.artifacts)
      setTampered(false)
      setVerified(null)
    }
  }

  const verify = async () => {
    if (!entries.length) return
    const res = await callVerify('/api/chain/verify', { artifacts: entries })
    if (res) setVerified(res)
  }

  const tamperEntry = async (idx: number) => {
    const res = await callTamper('/api/chain/tamper', { artifacts: entries, index: idx })
    if (res) { setEntries(res.artifacts); setTampered(true); setVerified(null) }
  }

  const reset = () => { setEntries([]); setChainId(null); setTampered(false); setVerified(null) }

  const exportChain = () => {
    const blob = new Blob([JSON.stringify(entries, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url; a.download = 'audit_chain.json'; a.click()
    URL.revokeObjectURL(url)
  }

  const integrityLabel = verified === null ? 'Not checked' : verified.valid ? 'INTACT' : 'BROKEN'
  const integrityColor = verified === null ? 'var(--text-secondary)' : verified.valid ? 'var(--ibm-teal-30)' : 'var(--ibm-magenta-40)'

  return (
    <div className="p-4 max-w-4xl mx-auto">
      <p className="font-mono text-xs mb-4" style={{ color: 'var(--text-secondary)' }}>
        Build a server-owned audit chain, then test whether its history is still intact.
      </p>

      {/* Controls */}
      <div className="flex gap-2 mb-4 flex-wrap">
        <button
          onClick={buildChain}
          disabled={loadingBuild}
          className="font-mono text-xs px-3 py-1.5 rounded"
          style={{ background: 'var(--ibm-blue-60)', color: '#fff', opacity: loadingBuild ? 0.7 : 1 }}
        >
          {loadingBuild ? 'Building…' : 'Build governed chain'}
        </button>
        <button
          onClick={verify}
          disabled={!entries.length || loadingVerify}
          className="font-mono text-xs px-3 py-1.5 rounded"
          style={{ background: 'var(--ibm-teal-60)', color: '#fff', opacity: (!entries.length || loadingVerify) ? 0.7 : 1 }}
        >
          {loadingVerify ? '…' : 'Verify Chain'}
        </button>
        <button
          onClick={reset}
          className="font-mono text-xs px-3 py-1.5 rounded ml-auto"
          style={{ color: 'var(--text-secondary)', border: '1px solid var(--border-ui)' }}
        >
          reset
        </button>
      </div>

      {/* Chain stats */}
      {(entries.length > 0 || chainId) && (
        <div className="grid grid-cols-3 gap-2 mb-4">
          <MetricCard value={String(entries.length)} label="CHAIN LENGTH" color="var(--ibm-blue-40)" />
          <MetricCard value={chainId ? chainId.slice(0, 12) + '…' : '—'} label="CHAIN ID" color="var(--ibm-cyan-30)" />
          <MetricCard value={integrityLabel} label="INTEGRITY" color={integrityColor} />
        </div>
      )}

      {/* Verification result */}
      {(buildError || verifyError || tamperError) && (
        <div role="alert" className="font-mono text-xs px-3 py-2 rounded mb-4" style={{ border: '1px solid #da1e28', color: '#da1e28' }}>
          {buildError ?? verifyError ?? tamperError}
        </div>
      )}
      {verified !== null && (
        <div className="font-mono text-xs px-3 py-2 rounded mb-4"
          style={{
            background: verified.valid ? 'rgba(8,186,132,0.08)' : 'rgba(255,126,182,0.08)',
            border: `1px solid ${verified.valid ? 'rgba(8,186,132,0.3)' : 'rgba(255,126,182,0.3)'}`,
            color: verified.valid ? 'var(--ibm-teal-30)' : 'var(--ibm-magenta-40)',
          }}
        >
          {verified.valid
            ? '// chain integrity verified — all links intact'
            : `// chain BROKEN — ${verified.errors.length} error(s): ${verified.errors[0]?.message ?? 'integrity check failed'}`}
        </div>
      )}

      {verified && (
        <dl className="grid grid-cols-3 gap-2 mb-4 text-sm">
          {[
            ['Content integrity', verified.content_integrity],
            ['Chain continuity', verified.chain_continuity],
            ['Signature', verified.signature_status],
            ['Anchor', verified.anchor_status],
            ['Completeness', verified.completeness],
          ].map(([label, value]) => (
            <div key={label} className="rounded p-2" style={{ border: '1px solid var(--border-ui)' }}>
              <dt style={{ color: 'var(--text-secondary)' }}>{label}</dt>
              <dd className="font-mono mt-1">{value}</dd>
            </div>
          ))}
        </dl>
      )}

      <p className="text-sm mb-4" style={{ color: 'var(--text-secondary)' }}>
        This in-memory demo proves content integrity and link continuity only.
        It does not prove a complete history, durable append-only storage,
        rollback protection, authenticity, or an external trust anchor.
      </p>

      {entries.length === 0 && (
        <div className="font-mono text-xs px-3 py-2 rounded" style={{ background: 'var(--bg-surface)', border: '1px solid var(--border-ui)', color: 'var(--text-secondary)' }}>
          // ask AEGIS to enforce three events and assign every chain coordinate
        </div>
      )}

      {/* Chain visualization */}
      <div className="space-y-2">
        {entries.map((entry, i) => {
          const checksum = entry.checksum ?? '—'
          const prev = entry.previous_audit_checksum

          return (
            <div key={i}>
              <div className="rounded p-3" style={{ border: `1px solid ${tampered ? 'rgba(255,126,182,0.4)' : 'var(--border-ui)'}`, background: 'var(--bg-surface)' }}>
                <div className="flex items-center gap-2 mb-2">
                  <span className="font-mono text-xs" style={{ color: 'var(--ibm-cyan-30)' }}>#{i}</span>
                  {i === 0 && (
                    <span className="font-mono text-[10px] px-1.5 py-0.5 rounded" style={{ background: 'rgba(15,98,254,0.12)', color: 'var(--ibm-blue-40)', border: '1px solid rgba(15,98,254,0.25)' }}>genesis</span>
                  )}
                  <StatusBadge status={entry.enforcement_result} />
                  {!tampered && (
                    <button
                      onClick={() => tamperEntry(i)}
                      disabled={loadingTamper}
                      className="font-mono text-[11px] px-2 py-0.5 rounded ml-auto"
                      style={{ color: 'var(--ibm-magenta-40)', border: '1px solid rgba(255,126,182,0.3)' }}
                    >
                      tamper
                    </button>
                  )}
                </div>
                <div className="font-mono text-xs space-y-1">
                  <div><span style={{ color: 'var(--text-secondary)' }}>checksum: </span><span style={{ color: 'var(--ibm-teal-30)' }}>{checksum.slice(0, 16)}…</span></div>
                  <div><span style={{ color: 'var(--text-secondary)' }}>prev: </span><span style={{ color: 'var(--text-secondary)' }}>{prev ? prev.slice(0, 16) + '…' : 'genesis'}</span></div>
                </div>
              </div>
              {i < entries.length - 1 && (
                <div className="font-mono text-xs mt-1" style={{ color: 'var(--ibm-blue-60)' }}>↓</div>
              )}
            </div>
          )
        })}
      </div>

      {/* Export */}
      {entries.length > 0 && (
        <button
          onClick={exportChain}
          className="mt-4 font-mono text-xs px-3 py-1.5 rounded"
          style={{ color: 'var(--text-secondary)', border: '1px solid var(--border-ui)' }}
        >
          Export Chain (JSON)
        </button>
      )}
    </div>
  )
}
