import React from 'react'

function escapeHtml(s) {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
}

export default function CodeSnippet({ content = '', showLines = true, highlightLine = null, idPrefix = '' }) {
  const lines = content.split('\n')
  return (
    <div style={{ fontFamily: 'var(--mono)', fontSize: 12, borderRadius: 6, overflow: 'auto', background: 'var(--bg2)', padding: 8 }}>
      <div style={{ display: 'flex', minWidth: 0 }}>
        {showLines && (
          <div style={{ textAlign: 'right', paddingRight: 8, userSelect: 'none', color: 'var(--text3)', flexShrink: 0 }}>
            {lines.map((_, i) => (
              <div key={i} style={{ height: 18, lineHeight: '18px' }}>{i + 1}</div>
            ))}
          </div>
        )}
        <div style={{ flex: 1, minWidth: 0 }}>
          {lines.map((line, index) => (
            <div
              key={index}
              id={idPrefix ? `${idPrefix}-${index + 1}` : undefined}
              style={{
                display: 'flex',
                minHeight: 18,
                alignItems: 'flex-start',
                background: highlightLine === index + 1 ? 'rgba(121, 198, 255, 0.12)' : 'transparent',
                padding: '0 2px',
              }}
            >
              <code style={{ whiteSpace: 'pre', flex: 1, color: 'var(--text)' }} dangerouslySetInnerHTML={{ __html: escapeHtml(line || ' ') }} />
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
