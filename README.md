# rfront

An HTTP frontend for Redis-compatible services.

## Features

- Supports HTTP, HTTP/2, and Websockets
- Automatic Let's Encrypt certificates and host binding
- Flexible access-control list for HTTP clients
- Returns the raw RESP outputs
- Works with Redis-compatible services like Tile38, Redcon, KeyDB, Uhaha, etc.

## Build and Run

```sh
make
./rfront --config config.json
```

## Configure

A `config.json` file is always required. 

### Configuration properties

- `hosts`: Array of publically accessible https hosts.
- `port`: Server port. Used for non-TLS http hosting.
- `cluster.addrs`: Array of Redis server addresses.
- `cluster.auth`: For authorizing the connection to the Redis servers.
- `acl.tokens`: Array of tokens for authorizing http clients for the current policy.
- `acl.access`: Default access for commands sent by http clients.
  - `allow`: Allow all incoming commands.
  - `disallow`: Deny all incoming commands.
- `acl.except`: Array of commands that are exceptions to `acl.access`.
- `namespaces`: Array of cluster and acl groups. See [namespaces](#namespaces).

### Automatic updates

Changes to the `acl` and `cluster` properties of the `config.json` file will
automatically be picked up by the running server, and do not require a server
restart.

### Configuration Examples

Bind the Redis server at `127.0.0.1:6379` to `http://localhost:8000` and
allow all commands from all clients, except for the `SHUTDOWN` command. 

```json
{
    "port": 8000,
    "cluster": {
        "addrs": [ "127.0.0.1:6379" ],
        "auth": ""
    },
    "acl": [
        {
            "tokens": [ "" ],
            "access": "allow",
            "except": [ "shutdown" ]
        }
    ]
}
```

Bind the Redis cluster at `10.0.0.1:6379,10.0.0.2:6379` to 
`https://example.com` and use the Redis `AUTH my-redis-auth`. 
This config includes two client tokens where one only allows the read-only 
commands `ping`, `get`, and `scan`. While the other also allows for the write
commands `set` and `del`.

```json
{
    "hosts": [ "example.com" ],
    "cluster": {
        "addrs": [ "10.0.0.1:6379", "10.0.0.2:6379" ],
        "auth": "my-redis-auth"
    },
    "acl": [
        {
            "tokens": [ "reader-client-token" ],
            "access": "disallow",
            "except": [ "ping", "get", "scan" ]
        }, {
            "tokens": [ "writer-client-token" ],
            "access": "disallow",
            "except": [ "ping", "get", "scan", "set", "del" ]
        }

    ]
}
```


## HTTP Client Examples 

Let's say you are using the first configuration above.

Here's a client connecting over websockets using the 
[wscat](https://github.com/websockets/wscat) client.

```
$ wscat -c ws://localhost:8000
connected (press CTRL+C to quit)
> ping
< +PONG

> set hello world
< +OK

> get hello
< $5
world

>
```

Notice that the responses are in the [RESP](https://redis.io/docs/reference/protocol-spec/) format.

If you want to send HTTP requests:

```
$ curl 'http://localhost:8000?cmd=ping'
+PONG
$ curl 'http://localhost:8000?cmd=set+hello+world'
+OK
$ curl 'http://localhost:8000?cmd=get+hello'
$5
world
```

If you require an ACL client token, as in the last configuration above, 
you can use the `token` querystring key such as:


```
$ wscat -c wss://example.com?token=reader-client-token
$ curl 'https://example.com?token=reader-client-token'
```

Or, you can provide the HTTP header `Authorization: Token reader-client-token`

## RESP Commands

For simple HTTP request, a basic command can sent using `cmd=name+arg+arg` in
the querystring, like:

```
$ curl 'http://localhost:8000?cmd=set+hello+world'
```

Or, you can send the raw RESP in the body of the request, like:

```
*3
$3
set
$5
hello
$5
world
```

## Namespaces

You can configure the server to point to multiple clusters and acl groups
using namespaces.

```json
{
    "hosts": [ "example.com" ],
    "namespaces": {
        "redis": {
            "cluster": {
                "addrs": [ "10.0.0.1:6379" ],
                "auth": "my-redis-auth"
            },
            "acl": [
                {
                    "tokens": [ "reader-client-token" ],
                    "access": "disallow",
                    "except": [ "ping", "set", "del", "get" ]
                }
            ]
        },
        "tile38": {
            "cluster": {
                "addrs": [ "10.0.0.1:9851" ],
                "auth": "my-tile38-auth"
            },
            "acl": [
                {
                    "tokens": [ "reader-client-token" ],
                    "access": "disallow",
                    "except": [ "ping", "set", "del", "intersects" ]
                }
            ]
        },
    }
}
```

Then the client URL would include the namespace like:

```
https://example.com/tile38?
https://example.com/redis?
```

