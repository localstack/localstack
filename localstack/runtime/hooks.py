import functools

from plugin import PluginManager, plugin

# plugin namespace constants
HOOKS_CONFIGURE_LOCALSTACK_CONTAINER = "localstack.hooks.configure_localstack_container"
HOOKS_INSTALL = "localstack.hooks.install"
HOOKS_ON_INFRA_READY = "localstack.hooks.on_infra_ready"
HOOKS_ON_INFRA_START = "localstack.hooks.on_infra_start"
HOOKS_PREPARE_HOST = "localstack.hooks.prepare_host"


def hook(namespace: str, priority: int = 0, **kwargs):
    """
    Decorator for creating functional plugins that have a hook_priority attribute.
    """

    def wrapper(fn):
        fn.hook_priority = priority
        return plugin(namespace=namespace, **kwargs)(fn)

    return wrapper


def hook_spec(namespace: str):
    """
    Creates a new hook decorator bound to a namespace.

    on_infra_start = hook_spec("localstack.hooks.on_infra_start")

    @on_infra_start()
    def foo():
        pass

    # run all hooks in order
    on_infra_start.run()
    """
    fn = functools.partial(hook, namespace=namespace)
    # attach hook manager and run method to decorator for convenience calls
    fn.manager = HookManager(namespace)
    fn.run = fn.manager.run_in_order
    return fn


class HookManager(PluginManager):
    def load_all_sorted(self, propagate_exceptions=False):
        """
        Loads all hook plugins and sorts them by their hook_priority attribute.
        """
        plugins = self.load_all(propagate_exceptions)
        # the hook_priority attribute is part of the function wrapped in the FunctionPlugin
        plugins.sort(
            key=lambda _fn_plugin: getattr(_fn_plugin.fn, "hook_priority", 0), reverse=True
        )
        return plugins

    def run_in_order(self, *args, **kwargs):
        """
        Loads and runs all plugins in order them with the given arguments.
        """
        for fn_plugin in self.load_all_sorted():
            fn_plugin(*args, **kwargs)

    def __str__(self):
        return "HookManager(%s)" % self.namespace

    def __repr__(self):
        return self.__str__()


# localstack container configuration (on the host)
configure_localstack_container = hook_spec(HOOKS_CONFIGURE_LOCALSTACK_CONTAINER)
# additional installers
install = hook_spec(HOOKS_INSTALL)
# prepare the host that's starting localstack
prepare_host = hook_spec(HOOKS_PREPARE_HOST)
# infra (runtime) lifecycle hooks
on_infra_start = hook_spec(HOOKS_ON_INFRA_START)
on_infra_ready = hook_spec(HOOKS_ON_INFRA_READY)
