def args2str(*args):
    return ", ".join(map(str, args))


def kwargs2str(**kwargs):
    return ", ".join([f"{key}={value}" for key, value in kwargs.items()])


def params2str(*args, **kwargs):
    argslist = list(map(str, args))
    kwargslist = [f"{key}={value}" for key, value in kwargs.items()]
    params = argslist + kwargslist
    return ", ".join(params)


if __name__ == '__main__':
    print(args2str(1, 2, 3, 4))
    print(kwargs2str(a=1, b=2))
    print(params2str(1, 2, 3, 4, a=1, b=2))
    print(params2str())
