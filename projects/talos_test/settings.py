from os.path import abspath
from os.path import basename
from os.path import dirname
from os.path import expanduser
from os.path import join
from os.path import normpath
from sys import path

PROJECT_PATH = dirname(abspath(__file__))
PROJECT_NAME = basename(PROJECT_PATH)
PROJECTS_PATH = normpath(join(PROJECT_PATH, '..'))

APPLICATIONS_PATH = normpath(join(PROJECTS_PATH, '../applications'))
DATABASES_PATH = normpath(join(PROJECTS_PATH, '../databases'))
CONFIGURATION_PATH = normpath(join(PROJECTS_PATH, '../configuration'))
STATIC_PATH = normpath(join(PROJECTS_PATH, '../static'))

path.insert(0, APPLICATIONS_PATH)

TALOS_LOGIN_URLS = (
    (('authenticated'), '/auth/login/'),
    (('knowledge_factor', 'ownership_factor'), '/auth/login-basic-otp/'),
    (('trust_factor', 'ownership_factor'), '/auth/login-cert-otp/')
)

AUTH_USER_MODEL = 'talos.Principal'

# See https://docs.djangoproject.com/en/1.10/howto/deployment/checklist/

ALLOWED_HOSTS = ['localhost', '127.0.0.1', gethostname(), gethostbyname(gethostname())]

# Password validation
# https://docs.djangoproject.com/en/1.10/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
        'OPTIONS':
        {
            'user_attributes': ('brief_name', 'full_name', 'email', 'phone'),
        }
    },
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator'},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]

AUTHENTICATION_BACKENDS = (
    'talos.compatibility.auth.AuthBackend',
)

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': PROJECT_NAME,
        'USER': PROJECT_NAME,
        'HOST': '127.0.0.1',
        'PORT': '5432',
        'ATOMIC_REQUESTS': True,
        'OPTIONS': {
            'sslmode': 'require',
            'sslrootcert': expanduser('~/.postgresql/root.crt'),
            'sslcert': expanduser('~/.postgresql/' + PROJECT_NAME + '.crt'),
            'sslkey': expanduser('~/.postgresql/' + PROJECT_NAME + '.key'),
            'options': '-c search_path=talos_test',
        },
    }
}


INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'talos'
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'talos.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

MIGRATION_MODULES = {
    'auth': None
}

ROOT_URLCONF = 'urls'

SECRET_KEY = 'yrn1w=jk5@d2l29@131=z((bv(!a+#feivd7osv5f4u31sfa_s'
CSRF_COOKIE_HTTPONLY = True
SECURE_BROWSER_XSS_FILTER = True
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_SECONDS = 3600
SECURE_SSL_REDIRECT = False
X_FRAME_OPTIONS = 'DENY'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'wsgi.application'

# Internationalization
# https://docs.djangoproject.com/en/1.10/topics/i18n/

DATE_FORMAT = 'Y-M-d'
DATETIME_FORMAT = 'Y-M-d H:i:s'
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_L10N = True
USE_TZ = True

# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/1.10/howto/static-files/

STATIC_URL = '/static/'
STATIC_ROOT = STATIC_PATH

TEMPLATES = [
    {
        'OPTIONS':
        {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages'
            ]
        },
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True
    }
]

TALOS_GEONAME_HEADER = 'HTTP_TALOS_GEONAME'

DEBUG = True

LOGGING = {
    'version': 1,
    'filters': {
        'require_debug_true': {
            '()': 'django.utils.log.RequireDebugTrue',
        }
    },
    'handlers': {
        'console': {
            'level': 'WARNING',
            'class': 'logging.StreamHandler',
            'filters': ['require_debug_true'],
        }
    },
    'loggers': {
        'root': {
            'handlers': ['console'],
            'level': 'WARNING',
        }
    }
}
