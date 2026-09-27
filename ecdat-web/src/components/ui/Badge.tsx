import React from 'react';

export type BadgeVariant = 'act-now' | 'monitor' | 'safe' | 'cyan' | 'purple' | 'neutral';

interface BadgeProps {
  children: React.ReactNode;
  variant?: BadgeVariant;
  className?: string;
  icon?: React.ReactNode;
  style?: React.CSSProperties;
}

export const Badge: React.FC<BadgeProps> = ({
  children,
  variant = 'neutral',
  className = '',
  icon,
  style,
}) => {
  return (
    <span className={`badge badge-${variant} ${className}`} style={style}>
      {icon && <span style={{ display: 'inline-flex', alignItems: 'center' }}>{icon}</span>}
      {children}
    </span>
  );
};
