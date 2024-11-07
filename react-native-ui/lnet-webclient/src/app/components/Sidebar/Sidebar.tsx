import '../../globals.css'
import './sidebar.css'

interface SidebarProps {
  username: string
  chats: string[]
}

// components/Sidebar/Sidebar.tsx
export const Sidebar = ({ username, chats }: SidebarProps) => {
    return (
      <aside className="sidebar">
        <div className="unselectable side-header">
          <h2>LNet</h2>
        </div>
        
        <nav className="channels-list">
          {chats.map((chat, index) => (
            <div key={index} className="unselectable channel-item">
              {chat}
            </div>
          ))}
        </nav>
  
        <div className="profile-section">
          <div className="profile-content">
            <div className="profile-avatar">
              {/* You can add an avatar image here later */}
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