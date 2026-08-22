import socket


def resolve(domain):
    try:
        return socket.gethostbyname(domain)
    except ( socket.gaierror, socket.herror, UnicodeError):
        return None