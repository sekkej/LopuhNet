"use client"

import './friendsmenu.css';
import { useEffect, useState } from "react";
import { sendAction } from '../../../wsbridge';

export const FriendsMenu = () => {
    const [username, setUsername] = useState('');
    const [resultMessage, setResultMessage] = useState('');
    const [friendsList, setFriendsList] = useState([]);

    useEffect(() => {
        async function updateFriendsList() {
            const result = await sendAction('list_friends', {});
            // // TODO: REMOVE AFTER DEBUGGING
            // for (let i = 0; i < 64; i++) {
            //   result.push({
            //     "name": "James Warren",
            //     "username": "jamezwarren",
            //     "avatar_seed": 2217336892,
            //     "public_key": "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",
            //     "public_signkey": "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",
            //     "userid": `2dbf765fd68d53da8421bdb3acc57${i}`
            //   })
            // }
            setFriendsList(result);
        };
    
        updateFriendsList();
    
        window.addEventListener('on_friend_request_accepted', updateFriendsList);
        window.addEventListener('on_friend_removed', updateFriendsList);
    
        return () => {
          window.removeEventListener('on_friend_request_accepted', updateFriendsList);
          window.removeEventListener('on_friend_removed', updateFriendsList);
        };
      }, []);
    
    const sendFriendRequest = async () => {
        if (!username) return;
        
        try {
            const result = await sendAction('send_friend_request', { username });
            setResultMessage(result[1]);
            setUsername('');
        } catch (error) {
            setResultMessage(`Failed to send friend request: ${error.message}`);
        }
    };
    
    const removeFriend = async (friendId) => {
        try {
            const result = await sendAction('remove_friend', { userid: friendId });
            if (!result[0]) {
                setResultMessage(`Failed to remove friend: ${result[1]}`);
            }
            setFriendsList(friendsList.filter(friend => friend.userid !== friendId));
        } catch (error) {
            setResultMessage(`Failed to remove friend: ${error.message}`);
        }
    };

    return (
        <div>
          <div className="chat main-centered">
            <div className="friends-management-panel">
              <div className="add-friend-panel">
                <div className="friend-panel-inputs">
                  <input
                    type="text"
                    placeholder="You can add friends with their username."
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                  />
                  <button onClick={sendFriendRequest} className="add-friend-button unselectable">Send friend request</button>
                </div>
                <div className="friend-panel-output unselectable">
                  <p className="friend-panel-result-message">{resultMessage}</p>
                </div>
              </div>
              <div className={`friends-list unselectable ${friendsList.length > 0 ? '' : "empty-friends-list"}`}>
                {friendsList.length > 0 ? (
                  friendsList.map((friend) => (
                    <div key={friend.userid} className="friends-list-element">
                      {friend.name}
                      <img
                        src="/remove-friend.svg"
                        style={{ width: '18px', height: '18px', marginRight: '8px' }}
                        onClick={() => removeFriend(friend.userid)}
                      />
                    </div>
                  ))
                ) : (
                  <p>Your friends will appear here...</p>
                )}
              </div>
            </div>
          </div>
        </div>
      );
};