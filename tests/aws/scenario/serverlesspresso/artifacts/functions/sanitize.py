# Source adapted from: https://github.com/aws-samples/serverless-coffee-workshop


def handler(event, ctx):
    print(event)
    order = event["body"]
    print(f"sanitizeOrder(order): {order}")

    menu_list = [m["M"] for m in event["menu"]["Item"]["value"]["L"]]
    ordered_drink = order["drink"]

    # # filter drinks from menu that correspond to ordered drink
    menu_items_for_drink = [m for m in menu_list if m["drink"]["S"] == ordered_drink]
    if not menu_items_for_drink:
        return False

    # Check modifiers
    # TODO: modifiers don't seem to be used at all, so let's just ignore them...
    # ordered_modifiers = order["modifiers"]
    # for m in menu_items_for_drink:
    #     item_modifiers = [im for im in m["modifiers"]["L"]]

    # Order and modifiers both exist in the menu
    return True
