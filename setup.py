
SETUP_INFO = dict(
    name = 'infi.devicemanager',
    version = '0.2.23',
    author = 'Thorsten Gehrmann',
    author_email = '32952468+thorstengehrmann@users.noreply.github.com',

    url = 'https://github.com/Infinidat/infi.devicemanager',
    license = 'BSD',
    description = """Python bindings to Windows Device Manager's APIs""",
    long_description = """Python bindings to Windows Device Managers' API""",

    # http://pypi.python.org/pypi?%3Aaction=list_classifiers
    classifiers = [
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: BSD License",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 3",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],

    install_requires = ['infi.cwrap',
'infi.exceptools',
'infi.instruct',
'infi.pyutils',
'infi.wioctl',
'setuptools'],
    namespace_packages = ['infi'],

    package_dir = {'': 'src'},
    package_data = {'': []},
    include_package_data = True,
    zip_safe = False,

    entry_points = dict(
        console_scripts = ['rescan = infi.devicemanager.scripts:rescan'],
        gui_scripts = [],
        ),
)

if SETUP_INFO['url'] is None:
    _ = SETUP_INFO.pop('url')

def setup():
    from setuptools import setup as _setup
    from setuptools import find_packages
    SETUP_INFO['packages'] = find_packages('src')
    _setup(**SETUP_INFO)

if __name__ == '__main__':
    setup()
