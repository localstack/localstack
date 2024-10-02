from functools import wraps


class ApiLimitation:
    """
    Alternative approach to track specific api-operation limitations
    This may be useful if service owners prefer to track limitation on operation level rather than on feature level
    Could also be used as an input for the coverage-docs in the future

    The ApiLimitation can be used as decorator for the specific operation, and adds a string with a description.
    In the scripts/feature_catalog_playground/playground.py we created a first PoC that also parses the decorated operations
    and adds the information to the final json output
    """

    def __init__(self, limitation: str):
        """
        Initialize the decorator with the message that will be stored for future retrieval.
        """
        self.limitation = limitation

    def __call__(self, func):
        """
        Decorate the function or method, storing the message as an attribute on the function.
        """

        @wraps(func)
        def wrapper(*args, **kwargs):
            # Call the original function
            return func(*args, **kwargs)

        # Attach the message to the function as an attribute for later retrieval
        wrapper.api_limitation_message = self.limitation
        return wrapper
