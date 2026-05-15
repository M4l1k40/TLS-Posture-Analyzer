import React, { useState, useEffect, useMemo } from 'react'
import CodeSnippet from './CodeSnippet'
import EvidenceBadge from './EvidenceBadge'

function getEvidenceLine(content = '', snippet = '') {
  if (!snippet) return null
  const index = content.indexOf(snippet)
  if (index === -1) {
    const short = snippet.split('\n')[0].trim()
    return short ? getEvidenceLine(content, short) : null
  }
  return content.slice(0, index).split('\n').length
}

export default function DecompilerViewer({ javaFiles = [], anomalies = [] }) {
  const [selectedIndex, setSelectedIndex] = useState(0)
  const [showFull, setShowFull] = useState(false)
  const [searchTerm, setSearchTerm] = useState('')
  const [highlightLine, setHighlightLine] = useState(null)

  const filteredFiles = useMemo(() => {
    const query = searchTerm.trim().toLowerCase()
    if (!query) return javaFiles.slice(0, 200)
    return javaFiles.filter(file => {
      const text = `${file.name} ${file.package || ''} ${file.path} ${file.content || ''}`.toLowerCase()
      return text.includes(query)
    }).slice(0, 200)
  }, [javaFiles, searchTerm])

  useEffect(() => {
    if (selectedIndex >= filteredFiles.length) {
      setSelectedIndex(Math.max(0, filteredFiles.length - 1))
    }
  }, [filteredFiles.length, selectedIndex])

  const selectedFile = filteredFiles[selectedIndex] || null
  const selectedAnomalies = selectedFile
    ? anomalies.filter(a => a.file === selectedFile.name || a.file === selectedFile.path || (a.evidence && a.evidence.file === selectedFile.path))
    : []

  useEffect(() => {
    if (highlightLine && selectedFile) {
      const element = document.getElementById(`decompiler-line-${highlightLine}`)
      if (element) {
        element.scrollIntoView({ behavior: 'smooth', block: 'center' })
      }
    }
  }, [highlightLine, selectedFile])

  function downloadFile(file) {
    const blob = new Blob([file.content || ''], { type: 'text/plain;charset=utf-8' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = file.name || 'file.java'
    a.click()
    URL.revokeObjectURL(url)
  }

  function openFile(index) {
    setSelectedIndex(index)
    setShowFull(true)
    setHighlightLine(null)
  }

  function jumpToEvidence(file, evidence) {
    const line = getEvidenceLine(file.content || '', evidence?.snippet || evidence?.issue || '')
    setHighlightLine(line)
    setShowFull(true)
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', alignItems: 'center' }}>
        <input
          value={searchTerm}
          onChange={e => setSearchTerm(e.target.value)}
          placeholder="Rechercher fichier, package ou code..."
          style={{ flex: 1, minWidth: 220, fontFamily: 'var(--mono)', fontSize: 12, padding: '8px 10px', borderRadius: 8, border: '1px solid var(--border)', background: 'var(--bg2)' }}
        />
        <button onClick={() => setShowFull(!showFull)} style={{ padding: '8px 12px' }}>
          {showFull ? 'Aperçu' : 'Affichage complet'}
        </button>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '320px 1fr', gap: 14, alignItems: 'start' }}>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 10, maxHeight: 720, overflowY: 'auto' }}>
          {filteredFiles.map((file, index) => (
            <button
              key={file.path || index}
              onClick={() => openFile(index)}
              style={{
                textAlign: 'left', padding: 10, borderRadius: 10,
                border: selectedIndex === index ? '1px solid var(--accent)' : '1px solid var(--border)',
                background: selectedIndex === index ? 'var(--bg3)' : 'var(--bg)',
                color: 'var(--text)',
                cursor: 'pointer',
                width: '100%',
              }}
            >
              <div style={{ fontFamily: 'var(--mono)', fontWeight: 600, marginBottom: 4 }}>{file.name}</div>
              <div style={{ fontSize: 11, color: 'var(--text3)', marginBottom: 4 }}>{file.package || 'no.package'} · {file.path}</div>
              <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', fontSize: 11, color: 'var(--text3)' }}>
                <span>{file.methods?.length || 0} méthodes</span>
                <span>{file.strings?.length || 0} strings</span>
              </div>
            </button>
          ))}
          {filteredFiles.length === 0 && (
            <div style={{ color: 'var(--text3)', padding: 12 }}>Aucun fichier Java correspondant.</div>
          )}
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          {selectedFile ? (
            <div style={{ border: '1px solid var(--border)', borderRadius: 12, padding: 14, background: 'var(--bg)' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', gap: 10, alignItems: 'flex-start' }}>
                <div>
                  <div style={{ fontFamily: 'var(--mono)', fontWeight: 700, fontSize: 14, marginBottom: 4 }}>{selectedFile.name}</div>
                  <div style={{ fontSize: 12, color: 'var(--text3)' }}>{selectedFile.package || 'no.package'} · {selectedFile.path}</div>
                </div>
                <button onClick={() => downloadFile(selectedFile)} style={{ padding: '8px 12px' }}>Télécharger</button>
              </div>

              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 10, marginTop: 12, fontSize: 12, color: 'var(--text3)' }}>
                <span>🔧 {selectedFile.methods?.length || 0} méthodes</span>
                <span>📝 {selectedFile.strings?.length || 0} strings</span>
                <span>{selectedAnomalies.length} anomalies liées</span>
              </div>

              <div style={{ marginTop: 12 }}>
                {showFull ? (
                  <CodeSnippet content={selectedFile.content || ''} showLines={true} highlightLine={highlightLine} idPrefix="decompiler-line" />
                ) : (
                  <CodeSnippet content={(selectedFile.content || '').split('\n').slice(0, 12).join('\n')} showLines={true} highlightLine={highlightLine} idPrefix="decompiler-line" />
                )}
              </div>

              {selectedAnomalies.length > 0 && (
                <div style={{ marginTop: 12, display: 'flex', flexWrap: 'wrap', gap: 8 }}>
                  {selectedAnomalies.slice(0, 4).map((a, idx) => (
                    <EvidenceBadge
                      key={idx}
                      label={a.issue || a.label || 'Anomalie'}
                      severity={a.severity || 'high'}
                      onClick={() => jumpToEvidence(selectedFile, a.evidence || a)}
                    />
                  ))}
                </div>
              )}

              {highlightLine && (
                <div style={{ marginTop: 10, fontSize: 12, color: 'var(--text3)' }}>
                  Ligne ciblée : {highlightLine}
                </div>
              )}
            </div>
          ) : (
            <div style={{ color: 'var(--text2)', fontSize: 13, padding: 14, border: '1px solid var(--border)', borderRadius: 12, background: 'var(--bg3)' }}>
              Sélectionne un fichier Java à afficher.
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
