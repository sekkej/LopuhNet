"use client"

import React, { useState } from 'react';
import { authorize } from '../../wsbridge';
import './authcomponent.css';

interface AuthComponentProps {
  onSuccess: () => void;
}

export const AuthComponent = ({ onSuccess }: AuthComponentProps) => {
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');

  const handleAuthorize = async () => {
    try {
      const authResult = await authorize(password, 'D:/DOCS/LopuhNet-GitHub/LopuhNet/client_async/account_data.json', 'D:/DOCS/LopuhNet-GitHub/LopuhNet/client/lnet.db');
      if (authResult[0] === false) {
        setError(authResult[1]);
      }
      else {
        onSuccess();
      }
    } catch (err) {
      setError('Authorization failed. Please try again.');
    }
  };

  return (
    <div className="auth-component">
      <h1>Welcome to LNet</h1>
      <h3>Authorization</h3>
      <input
        type="password"
        placeholder="Enter your password"
        value={password}
        onChange={(e) => setPassword(e.target.value)}
      />
      <button className="unselectable" onClick={handleAuthorize}>Authorize</button>
      {error && <div className="error-message">{error}</div>}
    </div>
  );
};