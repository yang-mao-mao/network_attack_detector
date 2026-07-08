from __future__ import annotations


DEMO_REQUESTS = [
    "GET /search?q=1%20union%20select%20password%20from%20users HTTP/1.1\r\nHost: demo.local\r\n\r\n",
    "GET /search?q=%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1\r\nHost: demo.local\r\n\r\n",
    "GET /run?cmd=cat%20/etc/passwd HTTP/1.1\r\nHost: demo.local\r\n\r\n",
]


def main() -> None:
    for index, request in enumerate(DEMO_REQUESTS, start=1):
        print(f"--- request {index} ---")
        print(request)


if __name__ == "__main__":
    main()

