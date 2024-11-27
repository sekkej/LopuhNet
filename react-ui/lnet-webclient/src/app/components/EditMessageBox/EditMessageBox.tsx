"use client"

import '../../globals.css'
import './editmessagebox.css'
import { sendAction } from '../../wsbridge';
import React, { useEffect, useRef, useState } from 'react';

export const EditMessageBox = () => {
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const [messageText, setMessageText] = useState('');

  useEffect(() => {
    const textarea = textareaRef.current;

    if (textarea) {
      const handleInput = () => {
        textarea.style.height = 'auto';
        if (textarea.scrollHeight < 128) {
          textarea.style.height = `${textarea.scrollHeight}px`;
        } else {
          textarea.style.height = `128px`;
        }
      };

      textarea.addEventListener('input', handleInput);

      return () => {
        textarea.removeEventListener('input', handleInput);
      };
    }
  }, []);

  const handleKeyDown = async (event: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (event.key === 'Enter') {
      event.preventDefault(); // Prevent new line on Enter key press

      if (messageText.trim()) {
        // Send the message
        const userId = (await sendAction('fetch_user', { username: 'jameswarren' }))[1].userid;
        await sendAction('send_message', { channel: userId, content: messageText });

        // Clear the input field
        setMessageText('');
      }
    }
  };

  return (
    <div className="edit-message-box">
      <div className="edit-message-text-area">
        <textarea
          placeholder="Enter your message here..."
          ref={textareaRef}
          rows="1"
          value={messageText}
          onChange={(e) => setMessageText(e.target.value)}
          onKeyDown={handleKeyDown}
        />
      </div>
    </div>
  );
};