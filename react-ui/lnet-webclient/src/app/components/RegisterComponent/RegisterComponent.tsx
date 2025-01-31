"use client"

import { useState, useEffect } from 'react';
import { register, sendAction } from '../../wsbridge';
import { OrbitProgress } from 'react-loading-indicators';

interface RegisterComponentProps {
  onSuccess: () => void;
  onDifferentMethod: () => void;
}

export const RegisterComponent = ({ onSuccess, onDifferentMethod }: RegisterComponentProps) => {
  const [address, setAddress] = useState('');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [captchaImage, setCaptchaImage] = useState('');
  const [captchaSolution, setCaptchaSolution] = useState('');
  const [isLoading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const handleRegisterButton = async () => {
    setLoading(true);
    try {
      if (captchaSolution == '') {
        const dbName = `${address.replace(':','#')}.db`;
        const regResult = await register(address, username, password, dbName);
        if (regResult[0] === false) {
          setError(regResult[1]);
        }
        else {
          onSuccess();
        }
      }
      else {
        await sendAction('solve_captcha', {solution: captchaSolution});
        setLoading(false);
      }
    } catch (err) {
      setError('Registration failed. Please try again.');
    }
  };

  useEffect(() => {
      const handleCaptcha = (event) => {
        setCaptchaImage(event.detail[0]);
        setLoading(false);
      };

      window.addEventListener('on_registration_captcha', handleCaptcha);

      return () => {
          window.removeEventListener('on_registration_captcha', handleCaptcha);
      };
  }, []);

  return (
    <div className="auth-component">
      <h1 className="unselectable">Welcome to LNet</h1>
      <h3 className="unselectable">Registration</h3>
      <input
        type="text"
        placeholder="Server address (i.e. host:port)"
        title="LNet is a decentalized network of servers, so each server has it's own users."
        value={address}
        onChange={(e) => setAddress(e.target.value)}
      />
      <input
        type="text"
        placeholder="Choose a username"
        title="Friend requests are sent to you by username."
        value={username}
        onChange={(e) => setUsername(e.target.value)}
      />
      <input
        type="password"
        placeholder="Choose a password"
        title="Please, choose wisely, you cannot restore the password!"
        value={password}
        onChange={(e) => setPassword(e.target.value)}
      />
      {
        captchaImage
          &&
        (<>
          <img
            className="captcha-image"
            src={`data:image/png;base64, ${captchaImage}`}
            width="324" height="108"
          />
          <input
            type="text"
            placeholder="Solve captcha challenge"
            value={captchaSolution}
            onChange={(e) => setCaptchaSolution(e.target.value)}
          />
        </>)
      }
      {isLoading && <OrbitProgress color="var(--accent)" size="small" />}
      {!isLoading && <button className="unselectable" onClick={handleRegisterButton}>Register</button>}
      <p className="unselectable" onClick={onDifferentMethod}>Already have an account?</p>
      {error && <div className="error-message">{error}</div>}
    </div>
  );
};