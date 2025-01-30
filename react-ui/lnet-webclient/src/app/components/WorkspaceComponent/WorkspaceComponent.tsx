"use client"

import './workspacecomponent.css';
import { MainMenu } from './MainMenu/MainMenu';
import { FriendsMenu } from './FriendsMenu/FriendsMenu';
import { ChatComponent } from './ChatComponent/ChatComponent';

interface WorkspaceComponentProps {
  chatId: string | null;
  selfUser: object | null;
}

export const WorkspaceComponent = ({ chatId, selfUser }: WorkspaceComponentProps) => {
  if (chatId == null) {
    return (<MainMenu></MainMenu>);
  }

  if (chatId === "friendsTab") {
    return (<FriendsMenu></FriendsMenu>);
  }

  return (<ChatComponent chatId={chatId} selfUser={selfUser}></ChatComponent>);
};