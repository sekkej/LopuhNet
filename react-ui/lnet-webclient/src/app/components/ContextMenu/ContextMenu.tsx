import '../../globals.css';
import './contextmenu.css';
import React, { useState, forwardRef, useEffect } from 'react';

interface ContextMenuProps {
  position: { x: number; y: number } | null;
  onClose: () => void;
  isOwnMessage: boolean;
}

// eslint-disable-next-line react/display-name
export const ContextMenu = forwardRef<HTMLDivElement, ContextMenuProps>(({ position, onClose, isOwnMessage }, ref) => {
    const [visible, setVisible] = useState(false);

    useEffect(() => {
        if (position) {
            setVisible(true);
        } else {
            setVisible(false);
        }
    }, [position]);

    useEffect(() => {
      const handleContextMenu = (event: MouseEvent) => {
        event.preventDefault();
        onClose();
      };

      document.addEventListener('contextmenu', handleContextMenu);

      return () => {
        document.removeEventListener('contextmenu', handleContextMenu);
      };
    }, [onClose]);

    if (!position) return null;

    let context_menu_items = (
        <div className="context-menu-options">
          <div className="context-menu-option">
            <img src="/copy-alt.svg" style={{ width: '16px', height: '16px', marginRight: '8px' }} />
            Copy
          </div>
          <div className="context-menu-option">
            <img src="/redo.svg" style={{ width: '16px', height: '16px', marginRight: '8px' }} />
            Reply
          </div>
        </div>
    );
    if (isOwnMessage) {
        context_menu_items = (
            <div className="context-menu-options">
                <div className="context-menu-option">
                  <img src="/copy-alt.svg" style={{ width: '16px', height: '16px', marginRight: '8px' }} />
                  Copy
                </div>
                <div className="context-menu-option">
                  <img src="/redo.svg" style={{ width: '16px', height: '16px', marginRight: '8px' }} />
                  Reply
                </div>
                <div className="context-menu-option">
                  <img src="/pencil.svg" style={{ width: '16px', height: '16px', marginRight: '8px' }} />
                  Edit Message
                </div>
                <div className="context-menu-option">
                  <img src="/trash.svg" style={{ width: '16px', height: '16px', marginRight: '8px' }} />
                  Delete Message
                </div>
            </div>
        );
    }

    return (
      <div
        className={`context-menu ${visible ? 'visible' : ''}`}
        style={{
          position: 'absolute',
          left: position.x,
          top: position.y,
        }}
        onClick={onClose}
        ref={ref}
      >
        {context_menu_items}
      </div>
    );
  }
);
