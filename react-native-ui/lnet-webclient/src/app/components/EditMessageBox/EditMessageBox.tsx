"use client"

import '../../globals.css'
import './editmessagebox.css'
import React, { useEffect, useRef } from 'react';

export const EditMessageBox = () => {
  const textareaRef = useRef(null);

  useEffect(() => {
    const textarea = textareaRef.current;

    if (textarea) {
      const handleInput = () => {
        textarea.style.height = 'auto';
        if (textarea.scrollHeight < 128) {
            textarea.style.height = `${textarea.scrollHeight}px`;
        }
        else {
            textarea.style.height = `128px`;
        }
      };

      textarea.addEventListener('input', handleInput);

      return () => {
        textarea.removeEventListener('input', handleInput);
      };
    }
  }, []);

  return (
    <div className="edit-message-box">
      <div className="edit-message-text-area">
        <textarea placeholder="Enter your message here..." ref={textareaRef} rows="1"></textarea>
      </div>
      <div className="edit-message-buttons">
        {/* Your buttons go here */}
      </div>
    </div>
  );
};
