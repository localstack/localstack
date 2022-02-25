def path_from_url(url: str) -> str:
    return "/%s" % str(url).partition("://")[2].partition("/")[2] if "://" in url else url
