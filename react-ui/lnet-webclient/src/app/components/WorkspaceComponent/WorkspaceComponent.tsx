"use client"

import './workspacecomponent.css';
import { useState } from 'react';
import { MainMenu } from './MainMenu/MainMenu';
import { FriendsMenu } from './FriendsMenu/FriendsMenu';
import { ChatComponent } from './ChatComponent/ChatComponent';

interface WorkspaceComponentProps {
  chatId: string | null;
  selfUser: object | null;
}

export const WorkspaceComponent = ({ chatId, selfUser }: WorkspaceComponentProps) => {
  const [chatMessages, setChatMessages] = useState([]);

  if (chatId == null) {
    return (<MainMenu/>);
  }

  if (chatId === "friendsTab") {
    return (<FriendsMenu/>);
  }

  return (<ChatComponent messages={chatMessages} setMessages={setChatMessages} chatId={chatId} selfUser={selfUser}/>);
};