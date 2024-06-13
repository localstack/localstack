import functools

from plux import PluginManager, plugin

# plugin namespace constants
HOOKS_CONFIGURE_LOCALSTACK_CONTAINER = "localstack.hooks.configure_localstack_container"
HOOKS_ON_RUNTIME_CREATE = "localstack.hooks.on_runtime_create"
HOOKS_ON_INFRA_READY = "localstack.hooks.on_infra_ready"
HOOKS_ON_INFRA_START = "localstack.hooks.on_infra_start"
HOOKS_ON_PRO_INFRA_START = "localstack.hooks.on_pro_infra_start"
HOOKS_ON_INFRA_SHUTDOWN = "localstack.hooks.on_infra_shutdown"
HOOKS_PREPARE_HOST = "localstack.hooks.prepare_host"


def hook(namespace: str, priority: int = 0, **kwargs):
    """
    Decorator for creating functional plugins that have a hook_priority attribute. Hooks with a higher priority value
    will be executed earlier.
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


configure_localstack_container = hook_spec(HOOKS_CONFIGURE_LOCALSTACK_CONTAINER)
"""Hooks to configure the LocalStack container before it starts. Executed on the host when invoking the CLI."""

prepare_host = hook_spec(HOOKS_PREPARE_HOST)
"""Hooks to prepare the host that's starting LocalStack. Executed on the host when invoking the CLI."""

on_infra_start = hook_spec(HOOKS_ON_INFRA_START)
"""Hooks that are executed right before starting the LocalStack infrastructure."""

on_runtime_create = hook_spec(HOOKS_ON_RUNTIME_CREATE)
"""Hooks that are executed right before the LocalstackRuntime is created. These can be used to apply
patches or otherwise configure the interpreter before any other code is imported."""

on_runtime_start = on_infra_start
"""Alias for on_infra_start. TODO: switch and deprecated `infra` naming."""

on_pro_infra_start = hook_spec(HOOKS_ON_PRO_INFRA_START)
"""Hooks that are executed after on_infra_start hooks, and only if LocalStack pro has been activated."""

on_infra_ready = hook_spec(HOOKS_ON_INFRA_READY)
"""Hooks that are execute after all startup hooks have been executed, and the LocalStack infrastructure has become
available."""

on_runtime_ready = on_infra_ready
"""Alias for on_infra_ready. TODO: switch and deprecated `infra` naming."""

on_infra_shutdown = hook_spec(HOOKS_ON_INFRA_SHUTDOWN)
"""Hooks that are execute when localstack shuts down."""

on_runtime_shutdown = on_infra_shutdown
"""Alias for on_infra_shutdown. TODO: switch and deprecated `infra` naming."""
