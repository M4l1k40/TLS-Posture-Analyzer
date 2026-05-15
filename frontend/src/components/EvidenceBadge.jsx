import React from 'react'

export default function EvidenceBadge({ label, severity = 'high', onClick }) {
  const color = severity === 'critical' ? '#ff6b6b' : severity === 'high' ? '#ffb86b' : '#8be9fd'
  return (
    <button onClick={onClick} style={{ background: 'transparent', border: `1px solid ${color}`, color, padding: '4px 8px', borderRadius: 6, fontSize: 12 }}>
      {label}
    </button>
  )
}
