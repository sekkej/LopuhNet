import '../../globals.css'
import './sidebar.css'
import React, { useState } from 'react';

interface SidebarProps {
  username: string;
  chats: { id: string; name: string }[];
  onUserClick: (userId: string) => void;
}

export const Sidebar = ({ username, chats, onUserClick }: SidebarProps) => {
  const [selectedChatId, setSelectedChatId] = useState<string | null>(null);

  const handleSelection = (chatId: string) => {
    setSelectedChatId(chatId);
    onUserClick(chatId);
  };

  return (
    <aside className="sidebar">
      <div className="unselectable side-header">
        <h2>LNet</h2>
      </div>
      
      <nav className="channels-list">
        {chats.map((chat) => (
          <div
            key={chat.id}
            className={`unselectable channel-item ${selectedChatId === chat.id ? 'selected' : ''}`}
            onClick={() => handleSelection(chat.id)}
          >
            {chat.name}
          </div>
        ))}
      </nav>

      <div className="profile-section">
        <div className="profile-content">
          <div className="profile-avatar">
            {/* TODO: Add an avatar image here */}
          </div>
          <div className="profile-info">
            <span className="profile-name">{username}</span>
            <span className="unselectable profile-status">Online</span>
          </div>
        </div>
      </div>
    </aside>
  );
};
