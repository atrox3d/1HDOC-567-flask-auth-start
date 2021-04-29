################################################################################
# https://stackoverflow.com/questions/14132789/relative-imports-for-the-billionth-time
################################################################################
import sys
import os


def add_import_absolute_folder(folder):
    #
    #   hack to add external private data
    #
    absolute = os.path.abspath(folder)
    print(f"{__name__}: add {absolute} to sys.path")
    sys.path.insert(0, absolute)
    print(f"{__name__}: sys.path: {sys.path}")


def add_parent_import():
    #
    #   hack to add external private data
    #
    print(f"{__name__}: add .. to sys.path")
    sys.path.insert(0, "..")
    print(f"{__name__}: sys.path: {sys.path}")


################################################################################
# https://stackoverflow.com/questions/14132789/relative-imports-for-the-billionth-time
# https://chrisyeh96.github.io/2017/08/08/definitive-guide-python-imports.html#case-3-importing-from-parent-directory
################################################################################
def parent_import():
    """
    add project root to sys.path to import from parent folder
    change the number of ".." accordingly
    """
    root = os.path.abspath(os.path.join(os.path.dirname(sys.argv[0]), ".."))
    print(f"adding project root tp sys.path: {root=}")
    sys.path.append(root)


################################################################################

def show_syspath():
    for n, p in enumerate(sys.path):
        print(f"{n=}, {p=}")


if __name__ == '__main__':
    if not __package__:
        """
        running this script directly
        """
        print("not package")
        import parentimport

        parentimport.parent_import()
        # parentimport.show_syspath()
        # from debug import Debug
        # from config import parse_arguments
    else:
        """
        importing this script from another script
        """
        print("__package__: ", __package__)
        from . import parentimport

        parentimport.parent_import()
        # parentimport.show_syspath()
        # from .debug import Debug  # ok
        # from .config import parse_arguments
