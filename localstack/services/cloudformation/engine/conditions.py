def evaluate_resource_condition(conditions: dict[str, bool], resource: dict) -> bool:
    if condition := resource.get("Condition"):
        return conditions.get(condition, True)
    return True
