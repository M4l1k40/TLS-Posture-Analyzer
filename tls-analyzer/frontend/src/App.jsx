import { useState, useEffect, useRef, useCallback } from 'react'
import { analyzeText, analyzeAPK, analyzeHAR, streamAI, checkHealth } from './api.js'

// ── Small components ──────────────────────────────────────────────────────────

function Badge({ severity }) {
  const cfg = {
    critical: { bg: '#3d1a1a', color: '#f85149', label: 'Critique' },
    high:     { bg: '#2d1f0a', color: '#d29922', label: 'Élevé' },
    medium:   { bg: '#0c2340', color: '#58a6ff', label: 'Moyen' },
    low:      { bg: '#0d2310', color: '#3fb950', label: 'Faible' },
    info:     { bg: '#1c1c40', color: '#bc8cff', label: 'Info' },
  }
  const c = cfg[severity] || cfg.info
  return (
    <span style={{ background: c.bg, color: c.color, fontSize: 10, fontWeight: 600, padding: '2px 7px', borderRadius: 20, whiteSpace: 'nowrap', letterSpacing: '0.02em' }}>
      {c.label}
    </span>
  )
}

function EnvTag({ env }) {
  const cfg = {
    prod:    { bg: '#1a1f40', color: '#79c0ff' },
    test:    { bg: '#2d1f0a', color: '#e3b341' },
    unknown: { bg: '#21262d', color: '#8b949e' },
  }
  const c = cfg[env] || cfg.unknown
  return (
    <span style={{ background: c.bg, color: c.color, fontSize: 10, fontWeight: 500, padding: '1px 6px', borderRadius: 4, flexShrink: 0 }}>
      {env.toUpperCase()}
    </span>
  )
}

function Card({ children, style }) {
  return (
    <div style={{
      background: 'var(--bg2)',
      border: '1px solid var(--border)',
      borderRadius: 'var(--radius-lg)',
      padding: '1rem 1.25rem',
      animation: 'fadeIn 0.2s ease',
      ...style
    }}>
      {children}
    </div>
  )
}

function SectionTitle({ icon, children, count }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}>
      <i className={`ti ti-${icon}`} style={{ fontSize: 15, color: 'var(--text2)' }} />
      <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--text)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>{children}</span>
      {count !== undefined && (
        <span style={{ background: 'var(--bg3)', color: 'var(--text2)', fontSize: 11, padding: '0 6px', borderRadius: 10, marginLeft: 'auto' }}>{count}</span>
      )}
    </div>
  )
}

function Metric({ val, label, color }) {
  return (
    <div style={{ background: 'var(--bg3)', borderRadius: 'var(--radius)', padding: '10px 12px', textAlign: 'center', flex: 1, border: '1px solid var(--border)' }}>
      <div style={{ fontSize: 24, fontWeight: 700, color: color || 'var(--text)', fontFamily: 'var(--mono)' }}>{val}</div>
      <div style={{ fontSize: 10, color: 'var(--text2)', marginTop: 2, textTransform: 'uppercase', letterSpacing: '0.05em' }}>{label}</div>
    </div>
  )
}

function StatusDot({ ok }) {
  return (
    <span style={{
      width: 8, height: 8, borderRadius: '50%', flexShrink: 0,
      background: ok ? 'var(--green)' : 'var(--red)',
      boxShadow: ok ? '0 0 6px #3fb95080' : '0 0 6px #f8514980',
    }} />
  )
}

function StreamBlock({ text, loading }) {
  const ref = useRef()
  useEffect(() => { if (ref.current) ref.current.scrollTop = ref.current.scrollHeight }, [text])

  if (!loading && !text) return null
  return (
    <div ref={ref} style={{
      background: 'var(--bg)',
      border: '1px solid var(--border)',
      borderRadius: 'var(--radius)',
      padding: '12px 14px',
      fontFamily: 'var(--mono)',
      fontSize: 12,
      lineHeight: 1.8,
      whiteSpace: 'pre-wrap',
      maxHeight: 400,
      overflowY: 'auto',
      color: 'var(--text)',
      marginTop: 10,
    }}>
      {loading && !text && (
        <span style={{ color: 'var(--text2)', animation: 'pulse 1s infinite' }}>● Analyse IA en cours…</span>
      )}
      {text}
      {loading && text && <span style={{ opacity: 0.5, animation: 'blink 0.8s step-end infinite' }}>▋</span>}
    </div>
  )
}

function DropZone({ onFile }) {
  const [drag, setDrag] = useState(false)
  const inputRef = useRef()

  const handle = (file) => {
    if (file && file.name.endsWith('.apk')) onFile(file)
    else alert('Fichier .apk requis')
  }

  return (
    <div
      onClick={() => inputRef.current.click()}
      onDragOver={e => { e.preventDefault(); setDrag(true) }}
      onDragLeave={() => setDrag(false)}
      onDrop={e => { e.preventDefault(); setDrag(false); handle(e.dataTransfer.files[0]) }}
      style={{
        border: `2px dashed ${drag ? 'var(--accent)' : 'var(--border)'}`,
        borderRadius: 'var(--radius-lg)',
        padding: '2rem',
        textAlign: 'center',
        cursor: 'pointer',
        transition: 'all 0.2s',
        background: drag ? '#0c2340' : 'transparent',
      }}
    >
      <input ref={inputRef} type="file" accept=".apk" style={{ display: 'none' }} onChange={e => handle(e.target.files[0])} />
      <i className="ti ti-package-import" style={{ fontSize: 32, color: drag ? 'var(--accent)' : 'var(--text2)', display: 'block', marginBottom: 8 }} />
      <div style={{ fontSize: 13, color: 'var(--text2)' }}>Glisse un fichier <strong style={{ color: 'var(--text)' }}>.apk</strong> ici ou clique pour parcourir</div>
      <div style={{ fontSize: 11, color: 'var(--text3)', marginTop: 4 }}>Extraction automatique des strings, NSC, endpoints</div>
    </div>
  )
}

// ── Main App ──────────────────────────────────────────────────────────────────

const TABS = [
  { key: 'input',     label: 'Entrées',    icon: 'file-import' },
  { key: 'endpoints', label: 'Endpoints',  icon: 'world' },
  { key: 'tls',       label: 'Checks TLS', icon: 'lock' },
  { key: 'anomalies', label: 'Anomalies',  icon: 'alert-triangle' },
  { key: 'ai',        label: 'Rapport IA', icon: 'sparkles' },
]

const DEMO_APK = `https://api.prod.myapp.com/v2/users
https://cdn.prod.myapp.com/assets/images
http://debug.internal.local/api/test
https://staging.myapp.io/api/v1
https://192.168.1.42/admin/panel
https://abc123.ngrok.io/webhook
dev.test.myapp.internal
https://api.prod.myapp.com/v2/auth/login
https://payments.prod.myapp.com/charge`

const DEMO_PROXY = `CONNECT api.prod.myapp.com:443 HTTP/1.1
Host: api.prod.myapp.com

GET http://insecure-legacy.myapp.com/ping HTTP/1.1
Host: insecure-legacy.myapp.com

CONNECT cdn.prod.myapp.com:443 HTTP/1.1`

const DEMO_NSC = `<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
  <base-config cleartextTrafficPermitted="true">
    <trust-anchors>
      <certificates src="system"/>
      <certificates src="user"/>
    </trust-anchors>
  </base-config>
  <debug-overrides>
    <trust-anchors>
      <certificates src="user"/>
    </trust-anchors>
  </debug-overrides>
</network-security-config>`

export default function App() {
  const [tab, setTab] = useState('input')
  const [health, setHealth] = useState(null)

  // Inputs
  const [apkText, setApkText]     = useState('')
  const [proxyText, setProxyText] = useState('')
  const [nscXml, setNscXml]       = useState('')

  // Results
  const [results, setResults] = useState(null)
  const [loading, setLoading] = useState(false)
  const [apkFile, setApkFile] = useState(null)
  const [harFile, setHarFile] = useState(null)

  // AI
  const [aiSummary, setAiSummary]       = useState('')
  const [aiRecs, setAiRecs]             = useState('')
  const [aiSumLoading, setAiSumLoading] = useState(false)
  const [aiRecLoading, setAiRecLoading] = useState(false)

  // Filter
  const [envFilter, setEnvFilter] = useState('all')
  const [search, setSearch]       = useState('')

  useEffect(() => { checkHealth().then(setHealth) }, [])

  // ── Analysis ──────────────────────────────────────────────────────────────

  async function runTextAnalysis() {
    setLoading(true)
    try {
      const data = await analyzeText({ apkText, proxyText, nscXml })
      setResults(data)
      setAiSummary(''); setAiRecs('')
      setTab('endpoints')
    } catch (e) {
      alert('Erreur backend : ' + e.message)
    } finally {
      setLoading(false)
    }
  }

  async function runAPKAnalysis(file) {
    setApkFile(file)
    setLoading(true)
    try {
      const data = await analyzeAPK(file)
      setResults(data)
      if (data.nsc_xml) setNscXml(data.nsc_xml)
      if (data.raw_strings) setApkText(data.raw_strings.slice(0, 5000))
      setAiSummary(''); setAiRecs('')
      setTab('endpoints')
    } catch (e) {
      alert('Erreur extraction APK : ' + e.message)
    } finally {
      setLoading(false)
    }
  }

  async function runHARAnalysis(file) {
    setHarFile(file)
    setLoading(true)
    try {
      const data = await analyzeHAR(file)
      // Fusionner avec les résultats existants si APK déjà analysé
      if (results) {
        const merged = {
          ...results,
          endpoints: [...results.endpoints, ...data.endpoints.filter(
            ep => !results.endpoints.find(e => e.value === ep.value)
          )],
          anomalies: [...results.anomalies, ...data.anomalies.filter(
            a => !results.anomalies.find(e => e.endpoint === a.endpoint && e.issue === a.issue)
          )],
          stats: {
            total:     results.stats.total + data.stats.total,
            prod:      results.stats.prod + data.stats.prod,
            test:      results.stats.test + data.stats.test,
            cleartext: results.stats.cleartext + data.stats.cleartext,
            critical:  (results.stats.critical || 0) + (data.stats.critical || 0),
            high:      (results.stats.high || 0) + (data.stats.high || 0),
          }
        }
        setResults(merged)
      } else {
        setResults(data)
      }
      setAiSummary(''); setAiRecs('')
      setTab('endpoints')
    } catch (e) {
      alert('Erreur import HAR : ' + e.message)
    } finally {
      setLoading(false)
    }
  }

  function buildSummaryPrompt() {
    if (!results) return ''
    const endpoints  = results.endpoints  || []
    const anomalies  = results.anomalies  || []
    const tls_checks = results.tls_checks || []
    const stats      = results.stats      || {}
    const total    = stats.total    ?? endpoints.length
    const prod     = stats.prod     ?? endpoints.filter(e => e.env === 'prod').length
    const test     = stats.test     ?? endpoints.filter(e => e.env === 'test').length
    const cleartext = stats.cleartext ?? endpoints.filter(e => e.value.startsWith('http://')).length

    return `Analyse de posture TLS/réseau Android :

Endpoints détectés (${total}) :
${endpoints.slice(0, 40).map(e => `- [${(e.env || 'unknown').toUpperCase()}] ${e.value}`).join('\n')}

Stats : ${prod} prod, ${test} test, ${cleartext} cleartext HTTP

Anomalies (${anomalies.length}) :
${anomalies.map(a => `- [${a.severity.toUpperCase()}] ${a.endpoint} → ${a.issue}`).join('\n') || '- Aucune anomalie'}

Vérifications TLS (NSC) :
${tls_checks.map(c => `- ${c.label}: ${c.detail} [${c.severity}]`).join('\n') || '- NSC non fourni'}

Génère un résumé "risques transport" avec :
1. Score de risque global /10 et justification
2. Top 3 risques critiques prioritaires
3. Analyse de la répartition prod/test des endpoints
4. Points positifs éventuels`
  }

  function buildRecsPrompt() {
    if (!results) return ''
    const anomalies  = results.anomalies  || []
    const tls_checks = results.tls_checks || []
    const stats      = results.stats      || {}
    const endpoints  = results.endpoints  || []
    const total    = stats.total    ?? endpoints.length
    const prod     = stats.prod     ?? endpoints.filter(e => e.env === 'prod').length
    const test     = stats.test     ?? endpoints.filter(e => e.env === 'test').length
    const cleartext = stats.cleartext ?? endpoints.filter(e => e.value.startsWith('http://')).length
    const hasPins  = tls_checks.find(c => c.label.includes('Pinning'))?.ok

    return `Contexte : application Android analysée.
Endpoints : ${total} (${prod} prod, ${test} test)
Cleartext HTTP : ${cleartext}
Anomalies critiques : ${anomalies.filter(a=>a.severity==='critical').map(a=>a.issue).join(', ') || 'aucune'}
Anomalies élevées : ${anomalies.filter(a=>a.severity==='high').map(a=>a.issue).join(', ') || 'aucune'}
NSC fourni : ${nscXml ? 'oui' : 'non'}, Pinning : ${hasPins ? 'oui' : 'non'}

Génère des recommandations concrètes et priorisées :

**P0 — Corrections immédiates**
**P1 — Durcissement TLS**
**P2 — Certificate Pinning** (quand l'appliquer, OkHttp CertificatePinner example)
**P3 — HSTS côté backend**
**Exemple NSC Android durci complet** (XML)
**Checklist finale audit`
  }

  async function runAISummary() {
    setAiSumLoading(true); setAiSummary('')
    try {
      await streamAI({
        prompt: buildSummaryPrompt(),
        mode: 'summary',
        onChunk: t => setAiSummary(p => p + t),
        onDone: () => setAiSumLoading(false),
      })
    } catch (e) {
      setAiSummary('Erreur : ' + e.message)
      setAiSumLoading(false)
    }
  }

  async function runAIRecs() {
    setAiRecLoading(true); setAiRecs('')
    try {
      await streamAI({
        prompt: buildRecsPrompt(),
        mode: 'recommendations',
        onChunk: t => setAiRecs(p => p + t),
        onDone: () => setAiRecLoading(false),
      })
    } catch (e) {
      setAiRecs('Erreur : ' + e.message)
      setAiRecLoading(false)
    }
  }

  // ── Filtered endpoints ────────────────────────────────────────────────────

  const filteredEndpoints = (results?.endpoints || []).filter(ep => {
    const matchEnv = envFilter === 'all' || ep.env === envFilter
    const matchSearch = !search || ep.value.toLowerCase().includes(search.toLowerCase())
    return matchEnv && matchSearch
  })

  // ── Render ────────────────────────────────────────────────────────────────

  const s = results?.stats || {}
  const anomalyCount = results?.anomalies?.length || 0

  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column' }}>
      {/* Header */}
      <header style={{ background: 'var(--bg2)', borderBottom: '1px solid var(--border)', padding: '0 2rem' }}>
        <div style={{ maxWidth: 1100, margin: '0 auto', display: 'flex', alignItems: 'center', gap: 12, height: 56 }}>
          <i className="ti ti-shield-lock" style={{ fontSize: 22, color: 'var(--accent)' }} />
          <span style={{ fontWeight: 700, fontSize: 16, letterSpacing: '-0.01em' }}>TLS Posture Analyzer</span>
          <span style={{ fontSize: 11, color: 'var(--text3)', background: 'var(--bg3)', padding: '2px 8px', borderRadius: 20, border: '1px solid var(--border)' }}>
            Network Security Audit
          </span>
          <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 8 }}>
            {health && (
              <span style={{ fontSize: 11, color: health.status === 'ok' ? 'var(--green)' : 'var(--red)', display: 'flex', alignItems: 'center', gap: 5 }}>
                <StatusDot ok={health.status === 'ok'} />
                Backend {health.status === 'ok' ? 'connecté' : 'déconnecté'}
                {health.api_key_set === false && ' · ⚠ API key manquante'}
              </span>
            )}
          </div>
        </div>
      </header>

      {/* Tabs */}
      <div style={{ background: 'var(--bg2)', borderBottom: '1px solid var(--border)' }}>
        <div style={{ maxWidth: 1100, margin: '0 auto', display: 'flex', gap: 0, paddingLeft: '1rem' }}>
          {TABS.map(t => (
            <button
              key={t.key}
              onClick={() => setTab(t.key)}
              style={{
                background: 'none', border: 'none', borderRadius: 0,
                borderBottom: tab === t.key ? '2px solid var(--accent)' : '2px solid transparent',
                color: tab === t.key ? 'var(--text)' : 'var(--text2)',
                fontWeight: tab === t.key ? 600 : 400,
                padding: '12px 16px',
                gap: 6, fontSize: 13,
                transition: 'color 0.15s',
              }}
            >
              <i className={`ti ti-${t.icon}`} style={{ fontSize: 14 }} />
              {t.label}
              {t.key === 'anomalies' && anomalyCount > 0 && (
                <span style={{ background: '#3d1a1a', color: 'var(--red)', fontSize: 10, fontWeight: 700, padding: '0 5px', borderRadius: 10 }}>
                  {anomalyCount}
                </span>
              )}
            </button>
          ))}
        </div>
      </div>

      {/* Content */}
      <main style={{ flex: 1, padding: '1.5rem 2rem' }}>
        <div style={{ maxWidth: 1100, margin: '0 auto' }}>

          {/* ── ENTRÉES ── */}
          {tab === 'input' && (
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.5rem' }}>
              {/* Left column */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                <Card>
                  <SectionTitle icon="package-import">Analyser un APK</SectionTitle>
                  <DropZone onFile={runAPKAnalysis} />
                  {apkFile && (
                    <div style={{ marginTop: 10, fontSize: 12, color: 'var(--green)', display: 'flex', gap: 6 }}>
                      <i className="ti ti-check" /> {apkFile.name} chargé
                    </div>
                  )}
                  {loading && (
                    <div style={{ marginTop: 10, fontSize: 12, color: 'var(--accent)', display: 'flex', gap: 6 }}>
                      <i className="ti ti-loader" style={{ animation: 'spin 1s linear infinite' }} /> Extraction en cours…
                    </div>
                  )}
                </Card>

                <Card>
                  <SectionTitle icon="file-upload">Importer logs proxy (HAR)</SectionTitle>
                  <p style={{ fontSize: 11, color: 'var(--text3)', marginBottom: 10 }}>
                    Fichier <code>.har</code> exporté depuis Burp Suite, mitmproxy ou Chrome DevTools
                  </p>
                  <label style={{
                    display: 'flex', alignItems: 'center', gap: 10,
                    border: '2px dashed var(--border)', borderRadius: 'var(--radius-lg)',
                    padding: '14px 16px', cursor: 'pointer', transition: 'border-color 0.2s',
                  }}
                    onMouseEnter={e => e.currentTarget.style.borderColor = 'var(--accent)'}
                    onMouseLeave={e => e.currentTarget.style.borderColor = 'var(--border)'}
                  >
                    <input
                      type="file" accept=".har"
                      style={{ display: 'none' }}
                      onChange={e => { if (e.target.files[0]) runHARAnalysis(e.target.files[0]) }}
                    />
                    <i className="ti ti-file-import" style={{ fontSize: 22, color: 'var(--text2)', flexShrink: 0 }} />
                    <div>
                      <div style={{ fontSize: 13, color: 'var(--text)' }}>
                        {harFile ? harFile.name : 'Cliquer pour importer un fichier .har'}
                      </div>
                      <div style={{ fontSize: 11, color: 'var(--text3)', marginTop: 2 }}>
                        Extraction automatique des endpoints interceptés
                      </div>
                    </div>
                    {harFile && <i className="ti ti-check" style={{ marginLeft: 'auto', color: 'var(--green)' }} />}
                  </label>
                  {harFile && (
                    <div style={{ marginTop: 8, fontSize: 11, color: 'var(--green)', display: 'flex', gap: 6 }}>
                      <i className="ti ti-check" /> {harFile.name} importé — endpoints fusionnés
                    </div>
                  )}
                </Card>

                <Card>
                  <SectionTitle icon="network">Logs Proxy (Burp / mitmproxy)</SectionTitle>
                  <textarea
                    value={proxyText}
                    onChange={e => setProxyText(e.target.value)}
                    placeholder={"CONNECT api.prod.example.com:443 HTTP/1.1\nGET http://insecure.test/ping HTTP/1.1\n..."}
                    style={{ minHeight: 120 }}
                  />
                </Card>
              </div>

              {/* Right column */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                <Card>
                  <SectionTitle icon="file-code">Strings APK (texte brut)</SectionTitle>
                  <p style={{ fontSize: 11, color: 'var(--text3)', marginBottom: 8 }}>
                    Output de <code>strings classes.dex</code>, smali, ressources…
                  </p>
                  <textarea
                    value={apkText}
                    onChange={e => setApkText(e.target.value)}
                    placeholder={"https://api.prod.example.com/v2\nhttp://debug.internal/test\ndev.staging.example.io\n..."}
                    style={{ minHeight: 120 }}
                  />
                </Card>

                <Card>
                  <SectionTitle icon="code">Network Security Config (XML)</SectionTitle>
                  <p style={{ fontSize: 11, color: 'var(--text3)', marginBottom: 8 }}>
                    <code>res/xml/network_security_config.xml</code>
                  </p>
                  <textarea
                    value={nscXml}
                    onChange={e => setNscXml(e.target.value)}
                    placeholder={'<?xml version="1.0" encoding="utf-8"?>\n<network-security-config>\n  ...\n</network-security-config>'}
                    style={{ minHeight: 130, fontFamily: 'var(--mono)' }}
                  />
                </Card>

                <div style={{ display: 'flex', gap: 8 }}>
                  <button className="primary" onClick={runTextAnalysis} disabled={loading} style={{ flex: 1 }}>
                    {loading
                      ? <><i className="ti ti-loader" style={{ animation: 'spin 1s linear infinite' }} />Analyse…</>
                      : <><i className="ti ti-player-play" />Lancer l'analyse</>
                    }
                  </button>
                  <button onClick={() => { setApkText(DEMO_APK); setProxyText(DEMO_PROXY); setNscXml(DEMO_NSC) }}>
                    <i className="ti ti-wand" />Démo
                  </button>
                  <button onClick={() => { setApkText(''); setProxyText(''); setNscXml(''); setResults(null); setApkFile(null) }}>
                    <i className="ti ti-trash" />
                  </button>
                </div>
              </div>
            </div>
          )}

          {/* ── ENDPOINTS ── */}
          {tab === 'endpoints' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              {!results ? (
                <p style={{ color: 'var(--text2)', fontSize: 13 }}>Lance d'abord l'analyse dans l'onglet <strong>Entrées</strong>.</p>
              ) : (
                <>
                  <div style={{ display: 'flex', gap: 10 }}>
                    <Metric val={s.total}     label="Total"     />
                    <Metric val={s.prod}      label="Production"  color="#79c0ff" />
                    <Metric val={s.test}      label="Test/Staging" color="#e3b341" />
                    <Metric val={s.cleartext} label="HTTP clair"   color="var(--red)" />
                  </div>

                  <Card>
                    <div style={{ display: 'flex', gap: 8, marginBottom: 12, alignItems: 'center' }}>
                      <input
                        value={search}
                        onChange={e => setSearch(e.target.value)}
                        placeholder="Filtrer les endpoints…"
                        style={{ flex: 1, fontFamily: 'var(--mono)', fontSize: 12 }}
                      />
                      {['all', 'prod', 'test', 'unknown'].map(f => (
                        <button key={f} onClick={() => setEnvFilter(f)}
                          style={{ background: envFilter === f ? 'var(--accent)' : 'var(--bg3)', color: envFilter === f ? '#0d1117' : 'var(--text2)', padding: '4px 10px', fontSize: 11, fontWeight: 600 }}>
                          {f.toUpperCase()}
                        </button>
                      ))}
                    </div>
                    <div style={{ maxHeight: 480, overflowY: 'auto' }}>
                      {filteredEndpoints.length === 0 && (
                        <p style={{ color: 'var(--text3)', fontSize: 13, padding: 8 }}>Aucun endpoint trouvé.</p>
                      )}
                      {filteredEndpoints.map((ep, i) => (
                        <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '7px 4px', borderBottom: '1px solid var(--border)', fontSize: 12 }}>
                          <i className={`ti ti-${ep.type === 'url' ? 'link' : ep.type === 'ip' ? 'server' : 'world'}`}
                            style={{ fontSize: 13, color: 'var(--text3)', flexShrink: 0 }} />
                          <code style={{ flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', color: ep.value.startsWith('http://') ? 'var(--red)' : 'var(--text)' }}>
                            {ep.value}
                          </code>
                          <EnvTag env={ep.env || 'unknown'} />
                          <span style={{ fontSize: 10, color: 'var(--text3)', flexShrink: 0 }}>{ep.type}</span>
                        </div>
                      ))}
                    </div>
                  </Card>
                </>
              )}
            </div>
          )}

          {/* ── TLS CHECKS ── */}
          {tab === 'tls' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              {!results ? (
                <p style={{ color: 'var(--text2)', fontSize: 13 }}>Lance d'abord l'analyse dans l'onglet <strong>Entrées</strong>.</p>
              ) : (
                <>
                  <Card>
                    <SectionTitle icon="lock" count={(results.tls_checks || []).length}>
                      Vérifications Network Security Config
                    </SectionTitle>
                    {!nscXml.trim() ? (
                      <div style={{ fontSize: 13, color: 'var(--text2)', display: 'flex', gap: 8 }}>
                        <i className="ti ti-info-circle" />
                        Aucun NSC fourni — collez le XML dans l'onglet Entrées.
                      </div>
                    ) : (results.tls_checks || []).map((c, i) => (
                      <div key={i} style={{ display: 'flex', alignItems: 'flex-start', gap: 10, padding: '10px 0', borderBottom: '1px solid var(--border)' }}>
                        <StatusDot ok={c.ok} />
                        <div style={{ flex: 1 }}>
                          <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 2 }}>{c.label}</div>
                          <div style={{ fontSize: 12, color: 'var(--text2)', fontFamily: 'var(--mono)' }}>{c.detail}</div>
                        </div>
                        <Badge severity={c.ok ? 'low' : c.severity} />
                      </div>
                    ))}
                  </Card>

                  <Card>
                    <SectionTitle icon="list-check">Checklist manuelle Android</SectionTitle>
                    {[
                      { label: 'TrustManager custom', detail: 'Vérifier checkServerTrusted() — ne doit pas être vide', severity: 'critical' },
                      { label: 'HostnameVerifier custom', detail: 'Chercher AllowAllHostnameVerifier ou verify() → true', severity: 'critical' },
                      { label: 'WebView onReceivedSslError', detail: 'Ne doit pas appeler handler.proceed()', severity: 'critical' },
                      { label: 'OkHttp CertificatePinner', detail: 'Vérifier si configuré avec SHA-256 pins', severity: 'high' },
                      { label: 'TLS 1.2 minimum', detail: 'OkHttp SSLSocketFactory — désactiver SSLv3, TLS 1.0', severity: 'medium' },
                      { label: 'Cipher suite moderne', detail: 'Vérifier ConnectionSpec.MODERN_TLS dans OkHttp', severity: 'medium' },
                    ].map((c, i) => (
                      <div key={i} style={{ display: 'flex', alignItems: 'flex-start', gap: 10, padding: '10px 0', borderBottom: '1px solid var(--border)' }}>
                        <i className="ti ti-checkbox" style={{ fontSize: 15, color: 'var(--text3)', flexShrink: 0, marginTop: 1 }} />
                        <div style={{ flex: 1 }}>
                          <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 2 }}>{c.label}</div>
                          <div style={{ fontSize: 12, color: 'var(--text2)' }}>{c.detail}</div>
                        </div>
                        <Badge severity={c.severity} />
                      </div>
                    ))}
                  </Card>
                </>
              )}
            </div>
          )}

          {/* ── ANOMALIES ── */}
          {tab === 'anomalies' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              {!results ? (
                <p style={{ color: 'var(--text2)', fontSize: 13 }}>Lance d'abord l'analyse dans l'onglet <strong>Entrées</strong>.</p>
              ) : (
                <>
                  <div style={{ display: 'flex', gap: 10 }}>
                    <Metric val={s.critical || 0} label="Critiques"  color="var(--red)" />
                    <Metric val={results.anomalies.filter(a=>a.severity==='high').length} label="Élevées" color="var(--orange)" />
                    <Metric val={results.anomalies.filter(a=>a.severity==='medium').length} label="Moyennes" color="var(--accent)" />
                    <Metric val={results.anomalies.length} label="Total" />
                  </div>

                  <Card>
                    <SectionTitle icon="alert-triangle" count={results.anomalies.length}>
                      Anomalies détectées
                    </SectionTitle>
                    {results.anomalies.length === 0 ? (
                      <div style={{ display: 'flex', gap: 8, fontSize: 13, color: 'var(--green)' }}>
                        <i className="ti ti-circle-check" /> Aucune anomalie détectée.
                      </div>
                    ) : results.anomalies.map((a, i) => (
                      <div key={i} style={{ display: 'flex', alignItems: 'flex-start', gap: 10, padding: '10px 0', borderBottom: '1px solid var(--border)' }}>
                        <i className="ti ti-alert-triangle" style={{ fontSize: 14, color: 'var(--red)', flexShrink: 0, marginTop: 2 }} />
                        <div style={{ flex: 1, minWidth: 0 }}>
                          <code style={{ fontSize: 11, display: 'block', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', marginBottom: 3 }}>
                            {a.endpoint}
                          </code>
                          <div style={{ fontSize: 12, color: 'var(--text2)' }}>{a.issue}</div>
                        </div>
                        <Badge severity={a.severity} />
                      </div>
                    ))}
                  </Card>
                </>
              )}
            </div>
          )}

          {/* ── RAPPORT IA ── */}
          {tab === 'ai' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              {!results ? (
                <p style={{ color: 'var(--text2)', fontSize: 13 }}>Lance d'abord l'analyse statique dans l'onglet <strong>Entrées</strong>.</p>
              ) : (
                <>
                  {/* Stats bar */}
                  <Card style={{ background: 'var(--bg3)', padding: '10px 16px' }}>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 16, fontSize: 12, color: 'var(--text2)', alignItems: 'center' }}>
                      <span><i className="ti ti-world" style={{ marginRight: 4 }} />{s.total} endpoints</span>
                      <span style={{ color: '#79c0ff' }}>{s.prod} prod</span>
                      <span>·</span>
                      <span style={{ color: '#e3b341' }}>{s.test} test</span>
                      <span>·</span>
                      <span style={{ color: 'var(--red)' }}>{s.critical || 0} critiques</span>
                      <span>·</span>
                      <span>{results.anomalies.length} anomalies</span>
                      {nscXml && <><span>·</span><span style={{ color: 'var(--green)' }}>NSC analysé</span></>}
                    </div>
                  </Card>

                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
                    <Card>
                      <SectionTitle icon="chart-bar">Résumé risques transport</SectionTitle>
                      <p style={{ fontSize: 12, color: 'var(--text2)', marginBottom: 10 }}>
                        Score global, top risques, répartition environnements.
                      </p>
                      <button onClick={runAISummary} disabled={aiSumLoading}>
                        <i className={`ti ti-${aiSumLoading ? 'loader' : 'sparkles'}`} style={aiSumLoading ? { animation: 'spin 1s linear infinite' } : {}} />
                        {aiSumLoading ? 'Analyse…' : 'Générer le résumé'}
                      </button>
                      <StreamBlock text={aiSummary} loading={aiSumLoading} />
                    </Card>

                    <Card>
                      <SectionTitle icon="bulb">Recommandations de durcissement</SectionTitle>
                      <p style={{ fontSize: 12, color: 'var(--text2)', marginBottom: 10 }}>
                        TLS durci, pinning, HSTS, exemple NSC complet.
                      </p>
                      <button onClick={runAIRecs} disabled={aiRecLoading}>
                        <i className={`ti ti-${aiRecLoading ? 'loader' : 'sparkles'}`} style={aiRecLoading ? { animation: 'spin 1s linear infinite' } : {}} />
                        {aiRecLoading ? 'Génération…' : 'Générer les recs'}
                      </button>
                      <StreamBlock text={aiRecs} loading={aiRecLoading} />
                    </Card>
                  </div>
                </>
              )}
            </div>
          )}

        </div>
      </main>
    </div>
  )
}
