# 🍀 LopuhNet
**LNet (LopuhNet)** — is a secure **P2P** (peer-to-peer) messenger, with an emphasis on **privacy**. In general, it uses **post-quantum key encapsulation mechanism** which has **NIST confirmed** recently and the [**ChaCha20Poly1305 cipher**](https://en.wikipedia.org/wiki/ChaCha20-Poly1305).

> [!IMPORTANT]
> Currently, LNet is under development and cannot be used on a mass scale.

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

# 💻 How to use the client-side API wrapper?
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

> [!NOTE]
> If you're interested not only in how to set up the server or use the client, then **you can view more below**.
> There you can find **the breakdown of how the protocol works, what encryption is being used, packet structure**.
> If you want to investigate deeply, you can view **project structure** defined below too.

# 🧱 Understanding the protocol, encryption and transmission
Long story short, the **protocol is quite basic** speaking in general context of how data is being encrypted and transmitted. First of all, **at the lowest level of networking** there are classes like `Packet` and `User`, in `User` we can **access recipient's public key for example**, and using `Packet` we can **construct primitive packet** containing JSON data.

However, **on the higher level of networking** we use `SecurePacket`, which automatically manages to **encrypt and decrypt data** based on our needs. It also **automatically signs** everything we send. We use our `private-signing key` **to sign outcoming messages**, recipient's `public-signing key` **to verify incoming messages**, recipient's `public key` **to encrypt outcoming data** and our `private key` **to decrypt incoming data**.
Talking in context of cryptography algorithms, `SecurePacket` uses:
1. [**HKDF**](https://cryptography.io/en/latest/hazmat/primitives/key-derivation-functions/#hkdf) [**over (over SHA-384)**](https://csrc.nist.gov/files/pubs/fips/180-2/final/docs/fips180-2.pdf) used to derive encryption key from generated ones.
2. [**ChaCha20Poly1305**](https://en.wikipedia.org/wiki/ChaCha20-Poly1305) used to encrypt and decrypt data.
3. [**Fips 203 (ML-KEM)**](https://csrc.nist.gov/pubs/fips/203/final) used as a key-encapsulation mechanism.
4. [**Fips 204 (ML-DSA)**](https://csrc.nist.gov/pubs/fips/204/final) used as a signing algorithm.

In case you don't understand why do we need to sign messages, the **LNet Server** has no clue what we're transmitting through it to each other, so it **cannot automatically verify what we send**; at least, **not supposed to**.

On the **higher level of networking**, we use `SecurePacket` to construct `Event`s, *one that is easier to understand*. `Event` class **represents an actual event, that is happened in network**, such as `MsgCreated`, `MsgEdited`, *etc*.

As you've probably guessed, on **the latest networking layer**, that is *the most simple and easiest to understand*, it's **the actual events** like `MsgCreated`, `MsgEdited`, *etc*.

Since **LNet is decentralized**, we **prefer to save everything locally**, including sensetive information like **account credentials** (e.g. keys). That means, we need to **securely save it**, for that we use:
1. [**PBKDF2**](https://cryptography.io/en/latest/hazmat/primitives/key-derivation-functions/#pbkdf2) [**over (over SHA-256)**](https://csrc.nist.gov/files/pubs/fips/180-2/final/docs/fips180-2.pdf) used to derive encryption key from the password.
2. [**AES-256**](https://www.nist.gov/publications/advanced-encryption-standard-aes-0) used to encrypt sensetive data based on encryption key.

Since we save everything locally, in **LNet Client** there are implemented:
1. `AccountData` class for easy and basic management of account data (without encryption).
2. `DataAutoSaver` class to automatically save account data securely (with encryption).
> [!TIP]
> It's **recommended to use** `DataAutoSaver`, as it's **easy-to-use** and **implements secure encryption**.

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
│   ├── wsbridge.py    # Basic WebSockets bridge in case you need to use this wrapper in different project.
│   ├── config.json    # Configuration file for the client
│   └── example.py     # Example usage of API Wrapper
├── react-ui
│   └── ... # Contains code of LNet Client user interface on React
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
