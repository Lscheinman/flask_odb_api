from apiserver.blueprints.home.models import ODB, get_datetime
from apiserver.utils import SECRET_KEY, SIGNATURE_EXPIRED, BLACK_LISTED, DB_ERROR, PROTECTED
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, TimedJSONWebSignatureSerializer

class userDB(ODB):

    def __init__(self, db_name="Users"):
        ODB.__init__(self, db_name)
        self.db_name = db_name
        self.ICON_SESSION = "sap-icon://activities"
        self.ICON_POST = "sap-icon://post"
        self.ICON_USER = "sap-icon://customer"
        self.ICON_BLACKLIST = "sap-icon://cancel"
        self.models = {
            "User": {
                "key": "integer",
                "createDate": "datetime",
                "userName": "string",
                "passWord": "string",
                "email": "string",
                "icon": "string",
                "class": "V"
            },
            "Message": {
                "key": "integer",
                "class": "V",
                "text": "string",
                "title": "string",
                "tags": "string",
                "sender": "string",
                "receiver": "string",
                "icon": "string",
                "createDate": "datetime"
            },
            "Session": {
                "key": "integer",
                "user": "string",
                "startDate": "datetime",
                "endDate": "datetime",
                "ipAddress": "string",
                "token": "string",
                "icon": "string",
                "class": "V"
            },
            "Blacklist": {
                "key": "integer",
                "token": "string",
                "user": "string",
                "session": "string",
                "createDate": "string",
                "icon": "string",
                "class": "V"
            }
        }

    def send_message(self, request):
        """
        Create a message and then wire relationships as following
        Session to message for Logging
        Sender to message for Activity of user
        Message to Receiver for Alerting
        :param request:
        :return:
        """
        if str(type(request)) == "<class 'werkzeug.local.LocalProxy'>":
            form = request.form.to_dict()
            sessionId = request.headers['SESSIONID']
        else: # For internal requests not coming from HTTP
            form = request
            sessionId = request['sessionId']

        msg = self.create_node(
            class_name="Message",
            text=form['text'],
            title=form['title'],
            sender=form['sender'],
            receiver=form['receiver'],
            createDate=get_datetime(),
            icon=self.ICON_POST)

        # create relations from sender to post and post to receiver
        senderKey = self.get_user(userName=form['sender'])[0].oRecordData['key']
        receiverKey = self.get_user(userName=form['receiver'])[0].oRecordData['key']
        msgKey = msg['data']['key']
        self.create_edge(fromNode=sessionId, toNode=msgKey, edgeType="Logged")
        self.create_edge(fromNode=senderKey, toNode=msgKey, edgeType="Sent")
        self.create_edge(fromNode=msgKey, toNode=receiverKey, edgeType="SentTo")
        # for tag in tags create a new node and relate it
        return msg

    def create_session(self, form, ip_address, token):
        """
        Create an object to track the activities of a user
        :param form:
        :param ip_address:
        :param token:
        :return:
        """
        session = self.create_node(
            class_name="Session",
            startDate=get_datetime(),
            ipAddress=ip_address,
            token=token,
            createDate=get_datetime(),
            user=form['userName'],
            icon=self.ICON_SESSION
        )

        return session

    def login(self, request):
        """
        Check the user password based on the supplied userName
        :param form:
        :return: token or none
        """
        form = request.form.to_dict(flat=True)
        ip_address = request.remote_addr

        r = self.client.command('''
        select passWord, key from User where userName = "{userName}"
        '''.format(userName=form["userName"]))
        if len(r) == 0:
            return {"message": "No user exists with name {userName}".format(userName=form["userName"]),
                    "session": None}
        password = r[0].oRecordData['passWord']
        key = r[0].oRecordData['key']
        if check_password_hash(password, form['passWord']):
            token = self.serialize_token(userName=form['userName'])
            session = self.create_session(form, ip_address, token)
            self.create_edge(fromNode=key, toNode=session['data']['key'], edgeType="UserSession")
            return {"token": token, "session": session['data']['key']}
        else:
            return {"message": "Incorrect password",
                    "session": None}

    def logout(self, request):
        """
        Look up a session and update the endDate with getTime
        Blacklist the token by creating a blacklist object with the token data
        :param request:
        :return:
        """
        # Look up the session and update the endDate with new getTime
        # Blacklist the token and associate with the Session

        r = request.form.to_dict(flat=True)
        dLOGOUT = get_datetime()
        self.update(class_name="Session", var="endDate", val=dLOGOUT, key=int(request.headers['SESSIONID']))
        blackListNode = self.create_node(
            class_name="Blacklist",
            createtDate=dLOGOUT,
            token=request.headers['AUTHORIZATION'],
            user=r['userName'],
            session=request.headers['SESSIONID'],
            icon=self.ICON_BLACKLIST
        )

        self.create_edge(edgeType="ClosedSession", fromNode=blackListNode['data']['key'], toNode=request.headers['SESSIONID'])

        return "User {userName} logged out from session {session} at {date}".format(
            userName=r['userName'], session=request.headers['SESSIONID'], date=dLOGOUT)

    def check_blacklist(self, token):
        """
        If there is a payload in getting a Blacklist with this token val, then it is Blacklisted
        :param token:
        :return:
        """
        bl = self.get_node(class_name="Blacklist", var="token", val=token)
        return bl

    def get_user(self, **kwargs):

        if "userName" in kwargs.keys():
            r = self.client.command('''
            select userName, email, createDate, key from User where userName = "{userName}"
            '''.format(userName=kwargs["userName"]))
        else:
            r = self.client.command('''
            select userName, email, createDate, key from User where email = "{email}"
            '''.format(email=kwargs["email"]))

        if len(r) == 0:
            return None
        else:
            return r

    def get_activity(self, request):

        u = self.get_user(userName=request.form.to_dict()['userName'])
        if u:
            sql = '''
            match {class: User, as: u, where: (key = %d)}.both(){class: V, as: e} return $elements
            ''' % (int(u[0].oRecordData['key']))
            r = self.client.command(sql)
            if len(r) > 0:
                nodes = []
                lines = []
                for i in r:
                    # Get the relationship types and each variable into the attributes array for a node
                    attributes = []
                    title = icon = status = class_name = None
                    for k in i.oRecordData.keys():
                        if str(type(i.oRecordData[k])) != "<class 'pyorient.otypes.OrientBinaryObject'>":
                            if k.lower() == 'key':
                                key = i.oRecordData[k]
                            elif k.lower() == 'icon':
                                icon = i.oRecordData[k]
                            elif k.lower() == 'title':
                                title = i.oRecordData[k]
                            elif k.lower() == 'status':
                                status = i.oRecordData[k]
                            elif k.lower() == 'class_name':
                                class_name = i.oRecordData[k]
                            elif k.lower() not in PROTECTED:
                                attributes.append({"value": i.oRecordData[k], "label": k})

                        else:
                            if i.oRecordData['key'] != u[0].oRecordData['key']:
                                if k.lower()[:2] == 'in':
                                    lines.append({'type': 'in', 'title': k[3:],
                                                  'to': i.oRecordData['key'],
                                                  'from': u[0].oRecordData['key']})
                                else:
                                    lines.append({'type': 'out', 'title': k[4:],
                                                  'from': i.oRecordData['key'],
                                                  'to': u[0].oRecordData['key']})


                    nodes.append(
                        self.format_node(key=key, title=title, class_name=class_name,
                        icon=icon, attributes=attributes, status=status))


                r = {"data": {'nodes': nodes, 'lines': lines}, "message": "%d activities found" % (len(nodes)-1)}
            else:
                r = {"data": u, "message": "No activity found"}

        else:
            r = {"data": None, "message": "No user named {userName} found".format(userName=self.get_user(userName=request.form.to_dict()['userName']))}
        return r

    def create_user(self, form):
        """
        If a user does not exist, encrypt the password for storage and create the user

        :param form:
        :return:
        """
        if not self.get_user(userName=form['userName'], email=form['email']):
            passWord = self.encrypt_password(form['passWord'])
            return self.create_node(
                class_name="User",
                passWord=passWord,
                userName=form['userName'],
                email=form['email'],
                createDate=get_datetime(),
                icon=self.ICON_USER
            )

    def delete_user(self, request):
        u = self.get_user(userName=request.form.to_dict()['userName'])
        if u:
            r = self.delete_node(class_name="User", key=int(u[0].oRecordData['key']))
            return {'data': r, 'message': "{userName} deleted".format(userName=request.form.to_dict()['userName'])}
        else:
            return {'data': None, 'message': "{userName} not found".format(userName=request.form.to_dict()['userName'])}

    def encrypt_password(self, plaintext_password):
        """
        Hash a plaintext string using PBKDF2. This is good enough according
        to the NIST (National Institute of Standards and Technology).

        :param plaintext_password: Password in plain text
        :type plaintext_password: str
        :return: str
        """
        if plaintext_password:
            return generate_password_hash(plaintext_password)

        return None

    def auth_user(self, token):
        auth = self.deserialize_token(token)
        if auth == SIGNATURE_EXPIRED:
            return {
                "status": 204,
                "message": SIGNATURE_EXPIRED
            }
        elif auth == BLACK_LISTED:
            return {
                "status": 204,
                "message": BLACK_LISTED
            }
        elif auth == DB_ERROR:
            return {
                "status": 500,
                "message": DB_ERROR
            }
        else:
            return None

    def deserialize_token(self, token):
        """
        Obtain a user from de-serializing a signed token.

        :param token: Signed token.
        :type token: str
        :return: User instance or None
        """
        private_key = TimedJSONWebSignatureSerializer(SECRET_KEY)
        try:
            if self.check_blacklist(token):
                return BLACK_LISTED
            else:
                decoded_payload = private_key.loads(token)
                return self.get_user(userName=decoded_payload.get('userName'))

        except Exception as e:
            if str(type(e)) == "<class 'itsdangerous.exc.SignatureExpired'>":
                return SIGNATURE_EXPIRED
            elif str(type(e)) == "<class 'pyorient.exceptions.PyOrientSQLParsingException'>":
                return DB_ERROR
            else:
                return None

    def serialize_token(self, userName, expiration=3600):
        """
        Sign and create a token that can be used for things such as resetting
        a password or other tasks that involve a one off token.

        :param expiration: Seconds until it expires, defaults to 1 hour
        :type expiration: int
        :return: JSON
        """
        private_key = SECRET_KEY

        serializer = TimedJSONWebSignatureSerializer(private_key, expiration)
        return serializer.dumps({'userName': userName}).decode('utf-8')







