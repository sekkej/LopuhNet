"use client"

import './chatcomponent.css'
import React, { useState, useEffect } from 'react';
import { Message } from '../Message/Message';
import { EditMessageBox } from '../EditMessageBox/EditMessageBox';

export const ChatComponent = () => {
  const [messages, setMessages] = useState([]);

  useEffect(() => {
    const handleNewMessage = (event) => {
      const newMessage = {
        content: event.detail[0].content,
        sender: event.detail[0].author.username,
        timestamp: new Date(event.detail[0].timestamp / 1e+6),
        isOwn: event.detail[0].author.username === "sekkej",
      };
      setMessages((prevMessages) => [...prevMessages, newMessage]);
    };

    window.addEventListener('on_message', handleNewMessage);

    return () => {
      window.removeEventListener('on_message', handleNewMessage);
    };
  }, []);

  return (
    <div>
      <div className="chat">
        {messages.map((message, index) => (
          <div className="message-instance" key={index}>
            <Message
              content={message.content}
              sender={message.sender}
              timestamp={message.timestamp}
              isOwn={message.isOwn}
              prevSender={index > 0 ? messages[index - 1].sender : null}
            />
          </div>
        ))}
      </div>
      <EditMessageBox />
    </div>
  );
};