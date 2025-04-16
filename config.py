import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY')
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    RECAPTCHA_SITE_KEY = '6LdpohorAAAAAFAQ6Bxi8XAxwT_0NZhdmmT4HJwD'
    RECAPTCHA_SECRET_KEY = '6LdpohorAAAAAN7ocYJV1Ze5PfbTH8Q9kPls_h-w'
