import WebSocket from 'isomorphic-ws';

export const ws = new WebSocket('ws://localhost:8765');

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
  await new Promise((resolve) => {
    ws.onopen = resolve;
  });

  console.log('WebSocket connection established');
  console.log(await sendAction('authorize', { trusted_consts_path: 'D:/DOCS/LopuhNet-GitHub/LopuhNet/client/trusted_consts.json', cached_data_path: 'D:/DOCS/LopuhNet-GitHub/LopuhNet/client/cached_data_sekkej.json', database_filename: 'D:/DOCS/LopuhNet-GitHub/LopuhNet/client/lnet_sekkej' }));
}

ws.onclose = () => {
  console.log('WebSocket connection closed');
};

ws.onerror = (error) => {
  console.error('WebSocket error:', error);
};