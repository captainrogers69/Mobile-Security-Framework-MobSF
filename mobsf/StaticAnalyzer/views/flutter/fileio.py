# -*- coding: utf_8 -*-
"""Safe file opening for attacker-controlled app files."""
import os
import stat

from mobsf.MobSF.security import is_pipe_or_link


def open_regular(path, max_size):
    """Open a regular file without following links or blocking on FIFOs.

    Returns a binary file object, or None if the path is a link, FIFO,
    device or other non-regular file, or is larger than max_size.
    """
    if is_pipe_or_link(path):
        return None
    flags = (os.O_RDONLY
             | getattr(os, 'O_NOFOLLOW', 0)
             | getattr(os, 'O_NONBLOCK', 0)
             | getattr(os, 'O_BINARY', 0))
    fd = os.open(path, flags)
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode) or st.st_size > max_size:
        os.close(fd)
        return None
    return os.fdopen(fd, 'rb')


SCAN_MAX_SIZE = 512 * 1024 * 1024
SCAN_CHUNK_SIZE = 4 * 1024 * 1024


def scan_regex(path, regex, tail=512, max_size=SCAN_MAX_SIZE,
               chunk_size=SCAN_CHUNK_SIZE, first_only=False):
    """Return regex matches in a file read in chunks, or None if unreadable.

    tail must exceed the longest possible match. Matches touching the end
    of a chunk wait for the next one; matches at the start of a carried
    tail were already judged with their preceding byte.
    """
    matches = []
    fobj = open_regular(path, max_size)
    if fobj is None:
        return None
    with fobj:
        buf = b''
        carried = False
        while True:
            chunk = fobj.read(chunk_size)
            eof = not chunk
            buf += chunk
            for match in regex.finditer(buf):
                if match.end() == len(buf) and not eof:
                    continue
                if carried and match.start() == 0:
                    continue
                matches.append(match)
                if first_only:
                    return matches
            if eof:
                return matches
            buf = buf[-tail:]
            carried = True
