from distutils.core import setup, Extension
from glob import glob

module1 = Extension('hash_extender',
                    sources = ['buffer.c', 'formats.c',
                               'test.c', 'tiger.c', 'util.c',
                               'hash_extender_engine.c', 
                               'hash_extender_py.c'],
                    libraries = ['crypto'])

setup (name = 'hash_extender',
       version = '',
       author      = ',
       description = '',
       ext_modules = [module1],
       license     = '',
       url         = '')