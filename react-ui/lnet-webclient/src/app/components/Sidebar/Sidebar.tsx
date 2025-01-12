import '../../globals.css'
import './sidebar.css'
import React, { useState } from 'react';

interface SidebarProps {
  username: string | null;
  chats: { id: string; name: string }[];
  onUserClick: (userId: string | null) => void;
}

export const Sidebar = ({ username, chats, onUserClick }: SidebarProps) => {
  const [selectedChatId, setSelectedChatId] = useState<string | null>(null);

  const handleSelection = (chatId: string | null) => {
    setSelectedChatId(chatId);
    onUserClick(chatId);
  };

  const closeChat = () => {
    handleSelection(null);
  }
  
  const authorized = username != null;
  
  let accountHeader = username || "Not logged in";
  accountHeader = accountHeader.length > 14 ? accountHeader.substring(0, 13) + '...' : accountHeader;

  return (
    <aside className="sidebar">
      <div className="unselectable side-header">
        <h2
          className={authorized ? "side-header-available" : ""}
          onClick={() => closeChat()}
        >
          LNet
        </h2>
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
          <div className="profile-general">
            <div className="profile-avatar">
              {/* TODO: Add an avatar image here */}
            </div>
            <div className="profile-info">
              <span className="profile-name">{accountHeader}</span>
              <span className="unselectable profile-status">{authorized ? "Online" : ""}</span>
            </div>
          </div>
          <div className="profile-extra">
            {authorized ?
              <img
                src="/friends.svg"
                style={{ width: '16px', height: '16px', marginRight: '8px' }}
                onClick={() => handleSelection("friendsTab")}
              />
              :
              ""
            }
          </div>
        </div>
      </div>
    </aside>
  );
};