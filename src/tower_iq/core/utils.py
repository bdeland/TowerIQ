def format_currency(value: float, symbol: str = "$", pad_to_cents: bool = False) -> str:
    """
    Formats a number into a Grafana-style abbreviated currency string up to decillion.
    Always rounds to 2 decimal places, no commas, negative sign always to the left of the symbol (e.g., -$1.23M), symbol prefix.
    If pad_to_cents is True, always show two decimal places (e.g., $0.00, $123.00) even for values < 1e3.
    """
    thresholds = [
        (1e33, "D"),
        (1e30, "N"),
        (1e27, "O"),
        (1e24, "S"),
        (1e21, "s"),
        (1e18, "Q"),
        (1e15, "q"),
        (1e12, "T"),
        (1e9,  "B"),
        (1e6,  "M"),
        (1e3,  "K"),
    ]
    abs_value = abs(value)
    for threshold, suffix in thresholds:
        if abs_value >= threshold:
            formatted = f"{abs_value / threshold:.2f}{suffix}"
            break
    else:
        if pad_to_cents:
            formatted = f"{abs_value:.2f}"
        else:
            formatted = f"{abs_value:.0f}" if abs_value == int(abs_value) else f"{abs_value:.2f}"
    if value < 0:
        return f"-{symbol}{formatted}"
    else:
        return f"{symbol}{formatted}"

def format_duration(seconds: float) -> str:
    """
    Formats a duration in seconds to DD:HH:MM:SS (days, hours, minutes, seconds).
    Always shows two digits for each field, omits days if zero.
    """
    seconds = int(seconds)
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, secs = divmod(rem, 60)
    if days > 0:
        return f"{days:02}:{hours:02}:{minutes:02}:{secs:02}"
    else:
        return f"{hours:02}:{minutes:02}:{secs:02}" 