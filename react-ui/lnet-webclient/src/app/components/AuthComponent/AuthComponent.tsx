"use client"

import React, { useState } from 'react';
import { authorize } from '../../wsbridge';
import './authcomponent.css';

interface AuthComponentProps {
  onSuccess: () => void;
}

export const AuthComponent = ({ onSuccess }: AuthComponentProps) => {
  const [address, setAddress] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');

  const handleAuthorize = async () => {
    // ! Remove after debugging
    setAddress("127.0.0.1:9229");
    setPassword("unit1secretPassword");

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
  };

  return (
    <div className="auth-component">
      <h1 className="unselectable">Welcome to LNet</h1>
      <h3 className="unselectable">Authorization</h3>
      <input
        type="text"
        placeholder="Server address (i.e. IP:Port)"
        value={address}
        onChange={(e) => setAddress(e.target.value)}
      />
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