import React from 'react';

interface CardProps {
  children: React.ReactNode;
  className?: string;
  interactive?: boolean;
  style?: React.CSSProperties;
  onClick?: () => void;
}

export const Card: React.FC<CardProps> = ({
  children,
  className = '',
  interactive = false,
  style,
  onClick,
}) => {
  const classes = `glass-card ${interactive ? 'glass-card-interactive' : ''} ${className}`;
  return (
    <div className={classes} style={style} onClick={onClick}>
      {children}
    </div>
  );
};
