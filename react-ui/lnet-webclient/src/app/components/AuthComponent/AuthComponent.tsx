"use client"

import React, { useState } from 'react';
import { authorize } from '../../wsbridge';
import './authcomponent.css';
import { OrbitProgress } from 'react-loading-indicators';

interface AuthComponentProps {
  onSuccess: () => void;
  onDifferentMethod: () => void;
}

export const AuthComponent = ({ onSuccess, onDifferentMethod }: AuthComponentProps) => {
  const [address, setAddress] = useState('');
  const [password, setPassword] = useState('');
  const [isLoading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const handleAuthorizeButton = async () => {
    setLoading(true);
    try {
      const dbName = `${address.replace(':','#')}.db`;
      const authResult = await authorize(address, password, dbName);
      if (authResult[0] === false) {
        setError(authResult[1]);
      }
      else {
        onSuccess();
      }
    } catch (err) {
      setError('Authorization failed. Please try again.');
    }
    setLoading(false);
  };

  return (
    <div className="auth-component">
      <h1 className="unselectable">Welcome to LNet</h1>
      <h3 className="unselectable">Authorization</h3>
      <input
        type="text"
        placeholder="Server address (i.e. host:port)"
        value={address}
        onChange={(e) => setAddress(e.target.value)}
      />
      <input
        type="password"
        placeholder="Enter your password"
        value={password}
        onChange={(e) => setPassword(e.target.value)}
      />
      {isLoading && <OrbitProgress color="var(--accent)" size="small" />}
      {!isLoading && <button className="unselectable" onClick={handleAuthorizeButton}>Authorize</button>}
      <p className="unselectable" onClick={onDifferentMethod}>Don't have an account?</p>
      {error && <div className="error-message">{error}</div>}
    </div>
  );
};