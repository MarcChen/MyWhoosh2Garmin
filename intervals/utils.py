import re


def sanitize_filename(name: str) -> str:
    """Sanitize string for safe file names."""
    # Replace any non-alphanumeric character (except - and _) with an underscore
    safe = re.sub(r"[^\w\-_.]", "_", name.strip())
    # Remove consecutive underscores
    safe = re.sub(r"_+", "_", safe)
    return safe.strip("_")
