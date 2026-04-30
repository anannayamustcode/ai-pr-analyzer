def extract_added_lines(patch: str) -> list[str]:
    if not patch:
        return []

    return [
        line[1:]  # remove leading "+"
        for line in patch.split("\n")
        if line.startswith("+") and not line.startswith("+++")
    ]


def diff_position_for_added_line(patch: str, added_line_number: int) -> int | None:
    if not patch:
        return None

    try:
        target_added_line = int(added_line_number)
    except (TypeError, ValueError):
        return None

    if target_added_line < 1:
        return None

    added_line = 0

    for position, line in enumerate(patch.splitlines(), start=1):
        if line.startswith("+") and not line.startswith("+++"):
            added_line += 1

            if added_line == target_added_line:
                return position

    return None
