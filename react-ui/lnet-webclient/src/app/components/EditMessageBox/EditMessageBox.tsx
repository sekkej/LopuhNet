"use client"

import '../../globals.css'
import './editmessagebox.css'
import { sendAction } from '../../wsbridge';
import React, { useEffect, useRef, useState } from 'react';

interface EditMessageBoxProps {
  chatId: string | null;
}

export const EditMessageBox = ({ chatId }: EditMessageBoxProps) => {
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
    if (event.key === 'Enter' && !event.shiftKey) {
      event.preventDefault();
  
      if (messageText.trim() && chatId) {
        const result = await sendAction('send_message', { channel: chatId, content: messageText });
  
        if (result[0]) {
          setMessageText('');
          console.log("a");
          const textarea = textareaRef.current;
          textarea.style.height = 'auto';
        }
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