import time, string, random, socket, pyorient
import click
from datetime import datetime
from dateutil.parser import parse
from apiserver.config import SERVER_NAME, SECRET_KEY, MAIL_PASSWORD, MAIL_USERNAME, COPILOT_DEV_TOKEN,\
    COPILOT_AUTH, COPILOT_URL, ODB_PSWD, ODB_USER


SERVER_NAME = SERVER_NAME
SECRET_KEY = SECRET_KEY
SIGNATURE_EXPIRED = 'Signature expired'
BLACK_LISTED = 'Blacklisted token'
DB_ERROR = "Database error"
PROTECTED = ["password"]
ODB_PSWD = ODB_PSWD
ODB_USER = ODB_USER

# mail settings
MAIL_SERVER = 'smtp.googlemail.com'
MAIL_PORT = 465
MAIL_USE_TLS = False
MAIL_USE_SSL = True

# gmail authentication
MAIL_USERNAME = MAIL_USERNAME
MAIL_PASSWORD = MAIL_PASSWORD
COPILOT_URL = COPILOT_URL
COPILOT_AUTH = COPILOT_AUTH
COPILOT_POST = 'https://api.cai.tools.sap/build/v1/dialog'
COPILOT_DEV_TOKEN = COPILOT_DEV_TOKEN

def get_datetime():
    """
    Utility function for returning a common standard datetime
    :return:
    """
    return datetime.fromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S')


def clean_concat(content):
    """
    Utility function for returning cleaned strings into a normalized format for keys
    :param content:
    :return:
    """
    try:
        content = content.lower().translate(str.maketrans('', '', string.punctuation)).replace(" ", "")
    except Exception as e:
        click.echo('%s %s' % (get_datetime(), str(e)))
        content = None

    return content


def clean(content):
    """
    Utility function for returning cleaned strings into a normalized format for keys
    :param content:
    :return:
    """
    try:
        content = str(content.replace("'", "").replace('"', ''))
    except Exception as e:
        click.echo('%s %s' % (get_datetime(), str(e)))
        content = None

    return content

def change_if_date(date_string, fuzzy=False):
    """
    Return a date if the string is possibly in a date format within the list of date_formats.

    :param date_string: str, string to check for date
    :param fuzzy: bool, ignore unknown tokens in string if True
    """
    date_formats = [
        '%a, %d %b %Y %H:%M:%S %z', '%a, %d %b %Y %H:%M:%S %Z', '%A, %D %B %Y %H:%M:%S %z', '%A, %D %B %Y %H:%M:%S %Z',
        '%A, %D %B %y %h:%m:%s %z', '%a, %d %b %y %h:%m:%s %z', '%a, %d %b %y %h:%m:%s %Z','%a, %D %b %Y %H:%M:%S %Z',
        '%m/%d/%y, %I:%M %p', '%M/%d/%y, %I:%M %p', '%M/%D/%y, %I:%M %p', '%M/%D/%Y, %I:%M %p',
        '%Y-%m-%d', '%Y/%m/%d', '%d-%m-%Y', '%d/%m/%Y', '%Y-%M-%D', '%Y/%M/%D', '%D-%M-%Y', '%D/%M/%Y',
        '%Y-%m-%d %H:%M:%S', '%Y/%m/%d %H:%M:%S', '%d-%m-%Y %H:%M:%S', '%d/%m/%Y %H:%M:%S',
        '%Y-%m-%d %H:%M', '%Y/%m/%d %H:%M', '%d-%m-%Y %H:%M', '%d/%m/%Y %H:%M',
                    ]
    try:
        parse(date_string, fuzzy=fuzzy)
        try:
            for df in date_formats:
                try:
                    dt = datetime.strptime(date_string, df)
                    return dt
                except:
                    pass
        except Exception as e:
            click.echo('%s %s' % (get_datetime(), str(e)))
        return False

    except ValueError:
        return False

def randomString(stringLength=15):

    letters = string.ascii_lowercase + string.hexdigits + string.ascii_uppercase + '!@#$%^&*()_,.>,<'
    return ''.join(random.choice(letters) for i in range(stringLength))


def get_host(**kwargs):
    possible_hosts = ["localhost"]
    possible_hosts.append(socket.gethostbyname_ex(socket.gethostname())[-1])
    if kwargs:
        click.echo('[%s_init__%s] Pausing to allow ODB setup' % (kwargs['db_name'], get_datetime()))
        time.sleep(1)
        click.echo('[%s_init__%s] Complete to allow ODB setup' % (kwargs['db_name'], get_datetime()))
        if len(possible_hosts) > 0:
            hostname = possible_hosts[0][:possible_hosts[0].rfind('.')]
            i = 2

            while i < 6:
                possible_hosts.append("%s.%d" % (hostname, i))
                i += 1
        for h in possible_hosts:
            click.echo('[%s_init__%s] attempting connection to %s' % (kwargs['db_name'], get_datetime(), h))
            client = pyorient.OrientDB("%s" % h, 2424)
            try:
                session_id = client.connect(kwargs['user'], kwargs['pswd'])
                click.echo('[%s_init__%s] successfully connected to %s' % (kwargs['db_name'], get_datetime(), h))
                return {"client": client, "session_id": session_id}
            except Exception as e:
                click.echo('[%s_init__%s] %s failed\n%s' % (kwargs['db_name'], get_datetime(), h, str(e)))

        return {"client": None, "session_id": None}

    else:
        print(possible_hosts)
