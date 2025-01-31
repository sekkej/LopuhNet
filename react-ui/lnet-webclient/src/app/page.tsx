"use client"

import { useEffect, useState } from 'react';
import { WorkspaceComponent } from './components/WorkspaceComponent/WorkspaceComponent';
import { Sidebar } from './components/Sidebar/Sidebar';
import { AuthComponent } from './components/AuthComponent/AuthComponent';
import { initializeWebSocket, sendAction } from './wsbridge';
import { RegisterComponent } from './components/RegisterComponent/RegisterComponent';

export default function Main() {
  const [loginMethod, setLoginMethod] = useState<string>('auth');
  const [chats, setChats] = useState([]);
  const [currentSelfUser, setCurrentSelfUser] = useState<object | null>(null);
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
      setCurrentSelfUser(selfUser);
    }

    async function fetchFriends() {
      const recvFriendsList = await sendAction('list_friends', {});
      const chats = recvFriendsList.map(user => ({ id: user.userid, name: user.name }));
      setChats(chats);
    }

    initialize();
  }, [isAuthorized]);

  useEffect(() => {
    async function updateFriendList() {
      const recvFriendsList = await sendAction('list_friends', {});
      const chats = recvFriendsList.map(user => ({ id: user.userid, name: user.name }));
      setChats(chats);
    }

    window.addEventListener('on_friend_request_accepted', updateFriendList);
    window.addEventListener('on_friend_removed', updateFriendList);

    return () => {
      window.removeEventListener('on_friend_request_accepted', updateFriendList);
      window.removeEventListener('on_friend_removed', updateFriendList);
    };
  }, []);

  const handleUserClick = (userId: string) => {
    setSelectedChatId(userId);
  };

  const loginComponent = (
    <>
      {loginMethod == "auth"
       &&
      <AuthComponent
        onSuccess={() => setIsAuthorized(true)}
        onDifferentMethod={() => setLoginMethod('reg')} 
      />}

      {loginMethod == "reg"
       &&
      <RegisterComponent
        onSuccess={() => setIsAuthorized(true)}
        onDifferentMethod={() => setLoginMethod('auth')} 
      />}
    </>
  );

  return (
    <>
      <Sidebar username={currentSelfUser?.username} chats={chats} onUserClick={handleUserClick} />
      <main className={isAuthorized ? "main-content" : "main-content main-centered"}>
        {!isAuthorized && loginComponent}
        {isAuthorized && <WorkspaceComponent chatId={selectedChatId} selfUser={currentSelfUser} />}
      </main>
    </>
  );
}
