import sys

"""
General utility functions
"""


def print_error_and_exit(arg0, *nargs, **kwargs):
    """ Wrapper function to print errors to stderr, so we don't interfere with e.g. extraction output. """
    arg0 = 'Error: ' + arg0 + '\n'
    sys.stderr.write(arg0, *nargs, **kwargs)
    sys.exit(1)


def print_warning(arg0, *nargs, **kwargs):
    """ Wrapper function to print warnings to stderr, so we don't interfere with e.g. extraction output. """
    arg0 = 'Warning: ' + arg0 + '\n'
    sys.stderr.write(arg0, *nargs, **kwargs)


def print_info(arg0, *nargs, **kwargs):
    """ Wrapper function to print info to stderr, so we don't interfere with e.g. extraction output. """
    arg0 = 'Info: ' + arg0 + '\n'
    sys.stderr.write(arg0, *nargs, **kwargs)


def chunker(seq, size):
    """ Utility function to chunk seq into a list of size sized sequences. """
    return (seq[pos:pos + size] for pos in range(0, len(seq), size))
