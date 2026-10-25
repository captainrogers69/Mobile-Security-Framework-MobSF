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
