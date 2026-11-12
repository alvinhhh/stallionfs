"""Access the input already admitted by the runner before test discovery."""
import sys


def runtime():
    admission = sys.modules.get('ci_git_input')
    if admission is None:
        raise RuntimeError('Qualified Git input must be initialized before test discovery')
    return admission.runtime()
