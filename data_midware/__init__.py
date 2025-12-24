from os import path
from dotenv import load_dotenv

__version__ = '0.1.0'
root_dir = path.dirname(__file__)
load_dotenv(path.join(root_dir, '.env'))
