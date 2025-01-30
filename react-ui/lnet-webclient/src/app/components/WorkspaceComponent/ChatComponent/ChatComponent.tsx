"use client"

import React, { useState, useEffect, useRef } from 'react';
import { Message } from '../../Message/Message';
import { EditMessageBox } from '../../EditMessageBox/EditMessageBox';

interface ChatComponentProps {
    chatId: string | null;
    selfUser: object | null;
}

export const ChatComponent = ({chatId, selfUser}: ChatComponentProps) => {
    const [messages, setMessages] = useState([]);
    const chatEndRef = useRef<HTMLDivElement | null>(null);

    useEffect(() => {
        if (!chatId) return;

        const handleNewMessage = (event) => {
            const newMessage = {
                content: event.detail[0].content,
                sender: event.detail[0].author.username,
                timestamp: new Date(event.detail[0].timestamp * 1000),
                isOwn: event.detail[0].author.username === selfUser?.username,
                messageDetails: event.detail[0],
                pending: false
            };

            setMessages((prevMessages) => {
                const updatedMessages = [...prevMessages, newMessage];
                if (updatedMessages.length > 500) {
                    return updatedMessages.slice(1);
                }
                return updatedMessages;
            });
        };

        window.addEventListener('on_message', handleNewMessage);

        return () => {
            window.removeEventListener('on_message', handleNewMessage);
        };
    }, [chatId]);

    const filteredMessages = messages.filter(
        m => (m.pending && m.onlyAccessibleIn === chatId)
            ||
        (
          m.messageDetails?.channel === chatId
                        ||
          (m.messageDetails?.channel === selfUser?.userid && chatId === m.messageDetails?.author.userid)
        )
      );
    
      return (
        <div>
          <div className="chat">
            {filteredMessages.map((message, index) => (
              <div className="message-instance" key={index}>
                <Message
                  content={message.content}
                  sender={message.sender}
                  timestamp={message.timestamp}
                  isOwn={message.isOwn}
                  prevSender={index > 0 ? filteredMessages[index - 1].sender : null}
                  pending={message.pending}
                />
              </div>
            ))}
            <div ref={chatEndRef} />
          </div>
          <EditMessageBox chatId={chatId} selfUser={selfUser} setMessages={setMessages} />
        </div>
      );
};