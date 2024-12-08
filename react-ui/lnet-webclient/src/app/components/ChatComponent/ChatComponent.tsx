"use client"

import './chatcomponent.css'
import React, { useState, useEffect } from 'react';
import { Message } from '../Message/Message';
import { EditMessageBox } from '../EditMessageBox/EditMessageBox';

interface ChatComponentProps {
  chatId: string | null;
  selfUserId: string | null;
}

export const ChatComponent = ({ chatId, selfUserId }: ChatComponentProps) => {
  const [messages, setMessages] = useState([]);

  useEffect(() => {
    if (!chatId) return;

    const handleNewMessage = (event) => {
      const newMessage = {
        content: event.detail[0].content,
        sender: event.detail[0].author.username,
        timestamp: new Date(event.detail[0].timestamp * 1000),
        isOwn: event.detail[0].author.username === "sekkej",
        messageDetails: event.detail[0],
      };
      setMessages((prevMessages) => [...prevMessages, newMessage]);
    };

    window.addEventListener('on_message', handleNewMessage);

    return () => {
      window.removeEventListener('on_message', handleNewMessage);
    };
  }, [chatId]);

  console.log(chatId);
  return (
    <div>
      <div className="chat">
        {messages.filter(
          m => m.messageDetails.channel === chatId
          ||
          (m.messageDetails.channel === selfUserId && chatId === m.messageDetails.author.id)
        )
        .map((message, index) => (
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
      <EditMessageBox chatId={chatId} />
    </div>
  );
};
