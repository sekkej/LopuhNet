# LopuhNet
**LNet (LopuhNet)** — is a secure **P2P** (peer-to-peer) messenger, with an emphasis on **privacy**. In general, it uses **post-quantum key encapsulation mechanism** which has **NIST confirmed** recently and the [**ChaCha20Poly1305 cipher**](https://en.wikipedia.org/wiki/ChaCha20-Poly1305).

It uses **TURN Server** to transmit **events**[^1] between *two or more* peers. It supports **DMs and Groups too**, however Groups support up to **10 members**. It uses **TCP** and all packets are being encrypted with **ML-KEM** and signed with **ML-DSA** and both are [confirmed by NIST.](https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards)

LNet uses [**SQLite**](https://www.sqlite.org/), but as the database management code located in `/shared/dbmanager.py`, that means you can rewrite it to use any other database management system.
The database is **decentralized**, that means, <ins>*if server is not modified*</ins>[^2][^3] then server **will <ins>not</ins> save your messages**; *however, this is an option, that can be turned off, if you expect the privacy.* Additionally, it is **decentralized** by the meaning of official servers, as it has not any of them, you'll need to setup your own or use existing one.

[^1]: Communication in LNet happens by events *(e.g.: MsgCreated, MsgDeleted, etc.)*, which allows you to not just simply share with messages, but do *a lot more* than that.
[^2]: *As you need to setup your own server to communicate or use existing one*, the server side of code **may be modified**, which means it can save transmitted data. **However, all transmitted data is encrypted**, so server have no clue what it transmits.
[^3]: Not only server can be modified, but the client side too. While **LNet does not support any server's intervention into the client's side**, you're allowed to **notify** *your users* to download your own version of the client.
