const WebSocket = require('ws');

const ws = new WebSocket('ws://localhost:8765');

ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  if (data.hasOwnProperty("event")) {
    console.log('event!:', data);
  }
};

async function sendAction(action, data) {
  let aid = Date.now();
  const payload = { action, "id": aid, ...data };
  ws.send(JSON.stringify(payload));

  const responsePromise = new Promise((resolve, reject) => {
    const handleResponse = (event) => {
      const data = JSON.parse(`${event}`);
      if (data.id === aid) {
        ws.off('message', handleResponse);
        resolve(data.result);
      }
    };

    ws.on('message', handleResponse);
  });
  return responsePromise;
}

async function main() {
  await new Promise((resolve) => {
    ws.onopen = resolve;
  });

  console.log('WebSocket connection established');
  console.log(await sendAction('authorize', { trusted_consts_path: 'D:/DOCS/LopuhNet-GitHub/LopuhNet/client/trusted_consts.json', cached_data_path: 'D:/DOCS/LopuhNet-GitHub/LopuhNet/client/cached_data_sekkej.json', database_filename: 'lnet_sekkej' }));
  let userid = (await sendAction('fetch_user', { username: 'jameswarren' }))[1].userid;
  console.log(userid);
  let msgresp = await sendAction('send_message', { channel: userid, content: 'hi there! message from bridge test js' });
  console.log(msgresp);
}

main().catch(console.error);

ws.onclose = () => {
  console.log('WebSocket connection closed');
};

ws.onerror = (error) => {
  console.error('WebSocket error:', error);
};