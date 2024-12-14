"use client"

import '../../globals.css'
import './editmessagebox.css'
import { sendAction } from '../../wsbridge';
import React, { useEffect, useRef, useState } from 'react';

interface EditMessageBoxProps {
  chatId: string | null;
  selfUser: object | null;
  setMessages: React.Dispatch<React.SetStateAction<any[]>>;
}

export const EditMessageBox = ({ chatId, selfUser, setMessages }: EditMessageBoxProps) => {
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
        setMessageText('');
        const textarea = textareaRef.current;
        textarea.style.height = 'auto';

        const pendingMessage = {
          content: messageText,
          sender: selfUser?.username,
          timestamp: new Date(),
          isOwn: true,
          pending: true,
          onlyAccessibleIn: chatId
        };
        setMessages((prevMessages) => [...prevMessages, pendingMessage]);

        const result = await sendAction('send_message', { channel: chatId, content: messageText });
  
        if (result[0]) {
          setMessages((prevMessages) =>
            prevMessages.filter((msg) =>
              msg !== pendingMessage
            )
          );
        }
        else {
          setMessages((prevMessages) =>
            prevMessages.map((msg) =>
              msg === pendingMessage ? { ...msg, sender: "Error!", content: result[1] } : msg
            )
          );
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