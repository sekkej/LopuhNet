import '../../globals.css'
import './contextmenu.css'
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
      const handleContextMenu = (event: MouseEvent) => {
        event.preventDefault();
        onClose()
      };

      document.addEventListener('contextmenu', handleContextMenu);

      return () => {
        document.removeEventListener('contextmenu', handleContextMenu);
      };
    }, [onClose]);

    useEffect(() => {
        if (position) {
            setVisible(true);
        } else {
            setVisible(false);
        }
    }, [position]);

    if (!position) return null;

    let context_menu_items = (
        <div className="context-menu-options">
          <div className="context-menu-option">Copy</div>
          <div className="context-menu-option">Reply</div>
        </div>
    )
    if (isOwnMessage) {
        context_menu_items = (
            <div className="context-menu-options">
                <div className="context-menu-option">Edit Message</div>
                <div className="context-menu-option">Delete Message</div>
                <div className="context-menu-option">Copy</div>
                <div className="context-menu-option">Reply</div>
            </div>
        )
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