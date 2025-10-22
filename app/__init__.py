# Make 'app.*' imports resolve to your existing 'App/*' modules.
import sys
from importlib import import_module as _M

def _alias(dst: str, src: str):
    sys.modules[dst] = _M(src)

# Alias leaf modules first so transitive imports from App.main work.
_alias('app.device', 'App.device')
_alias('app.state', 'App.state')
_alias('app.notify', 'App.Notify')
_alias('app.notify.emailer', 'App.Notify.emailer')
_alias('app.providers', 'App.Providers')
_alias('app.providers.base', 'App.Providers.base')
_alias('app.providers.demo', 'App.Providers.demo')
_alias('app.providers.boomnow_http', 'App.Providers.boomnow_http')
_alias('app.webhook', 'App.webhook')

# Finally alias the entrypoint
_alias('app.main', 'App.main')
