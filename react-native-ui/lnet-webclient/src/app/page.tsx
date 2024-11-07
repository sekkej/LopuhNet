import { EditMessageBox } from './components/EditMessageBox/EditMessageBox';
import { Message } from './components/Message/Message';
import { Sidebar } from './components/Sidebar/Sidebar';

export default function Main() {
  const chats = [
    "Alice",
    "Bob",
    "John Pork",
  ]

  const messages = [
    {
      content: "Hey, how's the project going?",
      sender: "Alice",
      timestamp: new Date("2024-11-06T18:00:00"),
      isOwn: false
    },
    {
      content: "It's going well!",
      sender: "Sekkej",
      timestamp: new Date("2024-11-06T18:01:00"), 
      isOwn: true
    },
    {
      content: "Just implementing the message component now.",
      sender: "Sekkej",
      timestamp: new Date("2024-11-06T18:01:30"), 
      isOwn: true
    },
    {
      content: "Great!",
      sender: "Alice",
      timestamp: new Date("2024-11-06T18:02:00"),
      isOwn: false
    },
    {
      content: "Let me know if you need any help with testing.",
      sender: "Alice",
      timestamp: new Date("2024-11-06T18:02:00"),
      isOwn: false
    },
    {
      content: "Thanks! I'll let you know once it's ready for review.",
      sender: "Sekkej", 
      timestamp: new Date("2024-11-06T18:03:00"),
      isOwn: true
    }
  ];

  return (
    <>
      <Sidebar username="Sekkej" chats={chats} />
      <main className="main-content">
        <div className="chat-container">
          {messages.map((msg, index) => (
            <Message
              key={index}
              content={msg.content}
              sender={msg.sender}
              timestamp={msg.timestamp}
              isOwn={msg.isOwn}
            />
          ))}
        </div>
        <EditMessageBox />
      </main>
    </>
  );
}
