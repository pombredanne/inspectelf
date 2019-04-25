from setuptools import setup
from subprocess import Popen, PIPE

# Install from git repo
Popen("pip install git+https://github.com/Knightingales/pydb.git", shell = True)

setup(name='inspectelf',
      version='0.1',
      description='inspectelf',
      url='',
      author='Team Bit65',
      author_email='',
      license='',
      packages=['inspectelf'],
      install_requires=['capstone',
      			'pyelftools',
      			'shove',
      			'filemagic',
      			'arpy',
      			'backports.lzma',
			'python-Levenshtein',
			'console_progressbar',
			'clang-5',
			'libarchive',
			'pymongo'
      ],
      dependency_links=['git+https://github.com/Knightingales/pydb.git'],
      zip_safe=False)
