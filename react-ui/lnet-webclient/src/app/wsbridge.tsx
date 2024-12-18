import WebSocket from 'isomorphic-ws';

export const ws = new WebSocket('ws://localhost:8765');
let isWSActive = false;

ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  if (data.hasOwnProperty("event")) {
    window.dispatchEvent(new CustomEvent(data.event, { detail: data.args }));
  }
};

export async function sendAction(action, data) {
    let aid = Date.now();
    const payload = { action, "id": aid, ...data };
    ws.send(JSON.stringify(payload));
  
    return new Promise((resolve) => {
      const handleResponse = (event) => {
        const data = JSON.parse(event.data);
        if (data.id === aid) {
          ws.removeEventListener('message', handleResponse);
          resolve(data.result);
        }
      };
  
      ws.addEventListener('message', handleResponse);
    });
}

export async function initializeWebSocket() {
  console.log('Attempting to establish WebSocket connection...');
  await new Promise((resolve) => {
    setTimeout(() => {
      if (isWSActive) {
        resolve();
      }
    }, 100)
  })
  console.log('WebSocket connection established');
  return true;
}

export async function authorize(password, autosave_path, database_path) {
  return await sendAction('authorize',
    {
      password: password,
      autosave_path: autosave_path,
      database_path: database_path
    }
  );
}

ws.onopen = () => {
  isWSActive = true;
}

ws.onclose = () => {
  console.log('WebSocket connection closed');
};

ws.onerror = (error) => {
  console.error('WebSocket error:', error);
};