import { ChatComponent } from './components/ChatComponent/ChatComponent';
import { Sidebar } from './components/Sidebar/Sidebar';
import { initializeWebSocket } from './wsbridge';

export default function Main() {
  const chats = [
    "Alice",
    "Bob",
    "John Pork",
  ]

  initializeWebSocket();

  return (
    <>
      <Sidebar username="sekkej" chats={chats} />
      <main className="main-content">
        <ChatComponent />
      </main>
    </>
  );
}
