def path_from_url(url: str) -> str:
    return f'/{url.partition("://")[2].partition("/")[2]}' if "://" in url else url


def hostname_from_url(url: str) -> str:
    return url.split("://")[-1].split("/")[0].split(":")[0]
