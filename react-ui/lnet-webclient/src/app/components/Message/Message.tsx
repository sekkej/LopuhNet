"use client"
import '../../globals.css'
import './message.css'
import React, { useState, useEffect, useRef } from 'react';
import { ContextMenu } from '../ContextMenu/ContextMenu';

interface MessageProps {
  content: string;
  sender: string;
  timestamp?: Date;
  isOwn?: boolean;
  prevSender: string | null;
  pending?: boolean;
}

export const Message = ({ content, sender, timestamp, isOwn = false, prevSender, pending = false }: MessageProps) => {
    const [contextMenuPosition, setContextMenuPosition] = useState<{ x: number; y: number } | null>(null);
    const contextMenuRef = useRef<HTMLDivElement>(null);
  
    const handleContextMenu = (event: React.MouseEvent<HTMLDivElement>) => {
      if ((event.target.classList + event.target.parentElement.classList).includes("context")) {
        return;
      }
      event.preventDefault();
      setContextMenuPosition({ x: event.clientX, y: event.clientY });
    };
  
    const closeContextMenu = () => {
      setContextMenuPosition(null);
    };
  
    useEffect(() => {
      const handleClickOutside = (event: MouseEvent) => {
        if (contextMenuRef.current && !contextMenuRef.current.contains(event.target as Node)) {
          closeContextMenu();
        }
      };
  
      const handleEscapeKey = (event: KeyboardEvent) => {
        if (event.key === 'Escape') {
          closeContextMenu();
        }
      };
  
      document.addEventListener('mousedown', handleClickOutside);
      document.addEventListener('keydown', handleEscapeKey);
  
      return () => {
        document.removeEventListener('mousedown', handleClickOutside);
        document.removeEventListener('keydown', handleEscapeKey);
      };
    }, []);
    
    console.log(prevSender);
    console.log(sender);

    return (
      <div
        className={`
          message-container
          ${isOwn ? 'message-own' : 'message-other'}
          ${prevSender === sender ? 'hide-sender' : ''}
          ${pending ? 'pending-message' : ''}
        `}
        onContextMenu={handleContextMenu}
      >
        <div className="message-header">
          <span className="sender">{sender}</span>
          {timestamp && (
            <span className="timestamp">
              {timestamp.toLocaleTimeString()}
            </span>
          )}
        </div>
        <div className="message-content">{content}</div>
        <ContextMenu
          position={contextMenuPosition}
          onClose={closeContextMenu}
          ref={contextMenuRef}
          isOwnMessage={isOwn}
        />
      </div>
    );
  };
