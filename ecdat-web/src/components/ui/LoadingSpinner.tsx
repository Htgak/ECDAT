import React from 'react';

export const LoadingSpinner: React.FC<{ size?: number; label?: string }> = ({
  size = 24,
  label,
}) => {
  return (
    <div style={{ display: 'inline-flex', alignItems: 'center', gap: '10px' }}>
      <div
        style={{
          width: size,
          height: size,
          border: '2px solid rgba(6, 182, 212, 0.2)',
          borderTopColor: 'var(--color-cyan)',
          borderRadius: '50%',
          animation: 'spin 0.8s linear infinite',
        }}
      />
      {label && <span style={{ color: 'var(--text-muted)', fontSize: '13px' }}>{label}</span>}
      <style>{`
        @keyframes spin {
          to { transform: rotate(360deg); }
        }
      `}</style>
    </div>
  );
};
