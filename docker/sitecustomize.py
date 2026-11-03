try:
    import apport_python_hook
    from sage.all import *
except ImportError:
    pass
else:
    apport_python_hook.install()
