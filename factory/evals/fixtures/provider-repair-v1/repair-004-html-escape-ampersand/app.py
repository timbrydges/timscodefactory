import html

def escape_untrusted(text):
    return text.replace("<", "&lt;").replace(">", "&gt;")
