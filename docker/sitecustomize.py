try:
    from sage.all import *
    import apport_python_hook
except ImportError:
    pass
else:
    apport_python_hook.install()
