"use client"

import { useEffect, useState } from 'react';
import { ChatComponent } from './components/ChatComponent/ChatComponent';
import { Sidebar } from './components/Sidebar/Sidebar';
import { AuthComponent } from './components/AuthComponent/AuthComponent';
import { initializeWebSocket, sendAction } from './wsbridge';

export default function Main() {
  const [chats, setChats] = useState([]);
  const [currentSelfUserId, setCurrentSelfUserId] = useState<string | null>(null);
  const [selectedChatId, setSelectedChatId] = useState<string | null>(null);
  const [isAuthorized, setIsAuthorized] = useState(false);

  useEffect(() => {
    async function initialize() {
      const wsInitialized = await initializeWebSocket();
      if (wsInitialized && isAuthorized) {
        await fetchFriends();
        await fetchSelfUserId();
      }
    }

    async function fetchSelfUserId() {
      const selfUser = await sendAction('get_self_user', {});
      setCurrentSelfUserId(selfUser.userid)
    }

    async function fetchFriends() {
      const friend_list = await sendAction('list_friends', {});
      const chats = friend_list.map(user => ({ id: user.userid, name: user.name }));
      setChats(chats);
    }

    initialize();
  }, [isAuthorized]);

  const handleUserClick = (userId: string) => {
    setSelectedChatId(userId);
  };

  return (
    <>
      <Sidebar username="sekkej" chats={chats} onUserClick={handleUserClick} />
      <main className={isAuthorized ? "main-content" : "main-content main-centered"}>
        {!isAuthorized && <AuthComponent onSuccess={() => setIsAuthorized(true)} />}
        {isAuthorized && <ChatComponent chatId={selectedChatId} selfUserId={currentSelfUserId} />}
      </main>
    </>
  );
}
