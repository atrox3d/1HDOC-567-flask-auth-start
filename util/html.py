# def h1(f):
#     def wrap(*args, **kwargs):
#         return "<h1>" + f(*args, **kwargs) + "<h1>"
#     return wrap
def html_tag(tagname):
    def decorator(fn):
        def wrapper(*args, **kwargs):
            return f"<{tagname}>" + fn(*args, **kwargs) + f"</{tagname}>"

        return wrapper

    return decorator


h1 = html_tag("h1")
em = html_tag("em")
