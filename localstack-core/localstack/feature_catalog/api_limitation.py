from functools import wraps


class ApiLimitation:
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
