# 🍀 LopuhNet
**LNet (LopuhNet)** — is a secure **P2P** (peer-to-peer) messenger, with an emphasis on **privacy**. In general, it uses **post-quantum key encapsulation mechanism** which has **NIST confirmed** recently and the [**ChaCha20Poly1305 cipher**](https://en.wikipedia.org/wiki/ChaCha20-Poly1305).

It uses **TURN Server** to transmit **events**[^1] between *two or more* peers. It supports **DMs and Groups too**. It uses **TCP** and all packets are being encrypted with **ML-KEM** and signed with **ML-DSA** and both are [confirmed by **NIST**.](https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards)

LNet uses [**SQLite**](https://www.sqlite.org/), but as the database management code located in `/shared/dbmanager.py`, that means you can rewrite it to use any other database management system.
The database is **decentralized** by default, that means, <ins>*if server is not modified*</ins>[^2][^3] then server **will <ins>not</ins> save your messages**. Additionally, it is **decentralized** by the meaning of official servers, as it has not any of them, you'll need to setup your own or use existing one from someone.

[^1]: Communication in LNet happens by events *(e.g.: MsgCreated, MsgDeleted, etc.)*, which allows you to not just simply share with messages, but do *a lot more* than that.
[^2]: *As you need to setup your own server to communicate or use existing one*, the server side of code **may be modified**, which means it can save transmitted data. **However, all transmitted data is encrypted**, so server have no clue what it transmits.
[^3]: Not only server can be modified, but the client side too. While **LNet does not support any server's intervention into the client's side**, you're allowed to **notify** *your users* to download your own version of the client.

> [!IMPORTANT]
> LNet currently designed to use it with [**asyncio**](https://pypi.org/project/asyncio/), hence the `client` and `server.py` **are discontinued**, however, **you still can contribute if you want!**
> 
> **Considering said, you're expected to use `client_async` and `server_async.py`!**
> 
> If you need to use the synchronous `client` or `server.py`, you have to implement some features and solve all issues by yourself.

# 📡 How to set up my own server?
LNet provides a *vanilla* server, that you can modify if you want. Note, that if you're going to modify the server-side, you'll probably need to modify the client-side itself too.
To set up your own server, follow these steps:
1. Install [**Python 3.10**](https://www.python.org/downloads/release/python-3100/) or above, if you haven't yet.
```bash
sudo apt install python3.10
```
2. Clone the repository, if you haven't yet:
```bash
git clone https://github.com/sekkej/LopuhNet.git
cd LopuhNet
```
3. Install requirements:
```bash
pip3.10 install -r server/requirements.txt
```
4. Optionally configure your server in `config.json`. If hosting on **a dedicated server**, you can delete the `client` and `client_async` directories.
5. Try running your server with:
```bash
python3.10 server/server_async.py
```
### If server is running successfully, without any error or an unexpected stop, you can try to connect to your server via the client.

# 💻 How to use the client?
LNet provides basic **asynchronous API wrapper** for *vanilla* server, that you can use any way you want. With that, you're able to create **your own user-interface of LNet client** or even **develop bots**.
1. Install [**Python 3.10**](https://www.python.org/downloads/release/python-3100/) or above, if you haven't yet.
```bash
sudo apt install python3.10
```
2. Clone the repository if you haven't yet:
```bash
git clone https://github.com/sekkej/LopuhNet.git
cd LopuhNet
```
3. Install requirements:
```bash
pip3.10 install -r client_async/requirements.txt
```
4. Optionally delete the `server` directory.
5. Try running an example code with:
```bash
python3.10 client_async/example.py
```
### If client is running successfully, without any error or an unexpected stop, it means you have successfully connected to the specified server.

# 📁 Project structure
```bash
LopuhNet
├── server
│   ├── server.py       # [DEPRECATED] Code of synchronous LNet Server
│   ├── config.json     # Configuration file for the server
│   └── server_async.py # Code of synchronous LNet Server
├── client
│   └── ... # [DEPRECATED] Code of synchronous LNet Client
├── client_async
│   ├── ...
│   ├── lnet.py        # API Wrapper of asynchronous LNet Client
│   ├── lnet_events.py # Events like MsgCreated, MsgDeleted, etc.
│   ├── lnet_types.py  # Types like Message, User, etc.
│   ├── config.json    # Configuration file for the client
│   └── example.py     # Example usage of API Wrapper
├── shared
│   ├── asyncio_events.py # Proper asynchronous events system
│   ├── base_logger.py    # Default logger instance
│   ├── basic_types.py    # Basic types: JSI (Json Serializable Interface), User, ServerAccount, Packet 
│   ├── dbmanager.py      # Database management code
│   ├── eventflags.py     # Flags for events
│   ├── packets.py        # Authentication and abstract packets
│   └── shared_utils.py   # Utilities for both client and server sides
└── README.md
```

# 🤗 Contributing
Contributions are welcome! Feel free to make any kind of improvement.
### Guidelines:
1. Ensure compatibility with Python 3.10+
2. Allow configuration for the feature you've implemented if it's possible